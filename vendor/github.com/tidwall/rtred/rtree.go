package rtred

import (
	"math"
	"sync"

	"github.com/tidwall/rtred/base"
)

type Iterator func(item Item) bool
type Item interface {
	Rect(ctx interface{}) (min []float64, max []float64)
}

type RTree struct {
	dims       int
	maxEntries int
	ctx        interface{}
	trs        []*base.RTree
	used       int
}

func New(ctx interface{}) *RTree {
	tr := &RTree{
		ctx:        ctx,
		dims:       20,
		maxEntries: 13,
	}
	tr.trs = make([]*base.RTree, 20)
	return tr
}

func (tr *RTree) Insert(item Item) {
	if item == nil {
		panic("nil item")
	}
	min, max := item.Rect(tr.ctx)
	if len(min) != len(max) {
		return // just return
		panic("invalid item rectangle")
	}
	if len(min) < 1 || len(min) > len(tr.trs) {
		return // just return
		panic("invalid dimension")
	}
	btr := tr.trs[len(min)-1]
	if btr == nil {
		btr = base.New(len(min), tr.maxEntries)
		tr.trs[len(min)-1] = btr
		tr.used++
	}
	amin := make([]float64, len(min))
	amax := make([]float64, len(max))
	for i := 0; i < len(min); i++ {
		amin[i], amax[i] = min[i], max[i]
	}
	btr.Insert(amin, amax, item)
}

func (tr *RTree) Remove(item Item) {
	if item == nil {
		panic("nil item")
	}
	min, max := item.Rect(tr.ctx)
	if len(min) != len(max) {
		return // just return
		panic("invalid item rectangle")
	}
	if len(min) < 1 || len(min) > len(tr.trs) {
		return // just return
		panic("invalid dimension")
	}
	btr := tr.trs[len(min)-1]
	if btr == nil {
		return
	}
	amin := make([]float64, len(min))
	amax := make([]float64, len(max))
	for i := 0; i < len(min); i++ {
		amin[i], amax[i] = min[i], max[i]
	}
	btr.Remove(amin, amax, item)
	if btr.IsEmpty() {
		tr.trs[len(min)-1] = nil
		tr.used--
	}
}
func (tr *RTree) Reset() {
	for i := 0; i < len(tr.trs); i++ {
		tr.trs[i] = nil
	}
	tr.used = 0
}
func (tr *RTree) Count() int {
	var count int
	for _, btr := range tr.trs {
		if btr != nil {
			count += btr.Count()
		}
	}
	return count
}

func (tr *RTree) Search(bounds Item, iter Iterator) {
	if bounds == nil {
		panic("nil bounds being used for search")
	}
	min, max := bounds.Rect(tr.ctx)
	if len(min) != len(max) {
		return // just return
		panic("invalid item rectangle")
	}
	if len(min) < 1 || len(min) > len(tr.trs) {
		return // just return
		panic("invalid dimension")
	}
	used := tr.used
	for i, btr := range tr.trs {
		if used == 0 {
			break
		}
		if btr != nil {
			if !search(btr, min, max, i+1, iter) {
				return
			}
			used--
		}
	}
}
func search(btr *base.RTree, min, max []float64, dims int, iter Iterator) bool {
	amin := make([]float64, dims)
	amax := make([]float64, dims)
	for i := 0; i < dims; i++ {
		if i < len(min) {
			amin[i] = min[i]
			amax[i] = max[i]
		} else {
			amin[i] = math.Inf(-1)
			amax[i] = math.Inf(+1)
		}
	}
	var ended bool
	btr.Search(amin, amax, func(item interface{}) bool {
		if !iter(item.(Item)) {
			ended = true
			return false
		}
		return true
	})
	return !ended
}

func (tr *RTree) KNN(bounds Item, center bool, iter func(item Item, dist float64) bool) {
	if bounds == nil {
		panic("nil bounds being used for search")
	}
	min, max := bounds.Rect(tr.ctx)
	if len(min) != len(max) {
		return // just return
		panic("invalid item rectangle")
	}
	if len(min) < 1 || len(min) > len(tr.trs) {
		return // just return
		panic("invalid dimension")
	}

	if tr.used == 0 {
		return
	}
	if tr.used == 1 {
		for i, btr := range tr.trs {
			if btr != nil {
				knn(btr, min, max, center, i+1, func(item interface{}, dist float64) bool {
					return iter(item.(Item), dist)
				})
				break
			}
		}
		return
	}

	type queueT struct {
		done bool
		step int
		item Item
		dist float64
	}

	var mu sync.Mutex
	var ended bool
	queues := make(map[int][]queueT)
	cond := sync.NewCond(&mu)
	for i, btr := range tr.trs {
		if btr != nil {
			dims := i + 1
			mu.Lock()
			queues[dims] = []queueT{}
			cond.Signal()
			mu.Unlock()
			go func(dims int, btr *base.RTree) {
				knn(btr, min, max, center, dims, func(item interface{}, dist float64) bool {
					mu.Lock()
					if ended {
						mu.Unlock()
						return false
					}
					queues[dims] = append(queues[dims], queueT{item: item.(Item), dist: dist})
					cond.Signal()
					mu.Unlock()
					return true
				})
				mu.Lock()
				queues[dims] = append(queues[dims], queueT{done: true})
				cond.Signal()
				mu.Unlock()
			}(dims, btr)
		}
	}
	mu.Lock()
	for {
		ready := true
		for i := range queues {
			if len(queues[i]) == 0 {
				ready = false
				break
			}
			if queues[i][0].done {
				delete(queues, i)
			}
		}
		if len(queues) == 0 {
			break
		}
		if ready {
			var j int
			var minDist float64
			var minItem Item
			var minQueue int
			for i := range queues {
				if j == 0 || queues[i][0].dist < minDist {
					minDist = queues[i][0].dist
					minItem = queues[i][0].item
					minQueue = i
				}
			}
			queues[minQueue] = queues[minQueue][1:]
			if !iter(minItem, minDist) {
				ended = true
				break
			}
			continue
		}
		cond.Wait()
	}
	mu.Unlock()
}
func knn(btr *base.RTree, min, max []float64, center bool, dims int, iter func(item interface{}, dist float64) bool) bool {
	amin := make([]float64, dims)
	amax := make([]float64, dims)
	for i := 0; i < dims; i++ {
		if i < len(min) {
			amin[i] = min[i]
			amax[i] = max[i]
		} else {
			amin[i] = math.Inf(-1)
			amax[i] = math.Inf(+1)
		}
	}
	var ended bool
	btr.KNN(amin, amax, center, func(item interface{}, dist float64) bool {
		if !iter(item.(Item), dist) {
			ended = true
			return false
		}
		return true
	})
	return !ended
}

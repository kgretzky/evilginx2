package base

import (
	"github.com/tidwall/tinyqueue"
)

type queueItem struct {
	node   *treeNode
	isItem bool
	dist   float64
}

func (item *queueItem) Less(b tinyqueue.Item) bool {
	return item.dist < b.(*queueItem).dist
}

// KNN returns items nearest to farthest. The dist param is the "box distance".
func (tr *RTree) KNN(min, max []float64, center bool, iter func(item interface{}, dist float64) bool) bool {
	var isBox bool
	knnPoint := make([]float64, tr.dims)

	bbox := &treeNode{min: min, max: max}

	for i := 0; i < tr.dims; i++ {
		knnPoint[i] = (bbox.min[i] + bbox.max[i]) / 2
		if !isBox && bbox.min[i] != bbox.max[i] {
			isBox = true
		}
	}
	node := tr.data
	queue := tinyqueue.New(nil)
	for node != nil {
		for i := 0; i < node.count; i++ {
			child := node.children[i]
			var dist float64
			if isBox {
				dist = boxDistRect(bbox, child)
			} else {
				dist = boxDistPoint(knnPoint, child)
			}
			queue.Push(&queueItem{node: child, isItem: node.leaf, dist: dist})
		}
		for queue.Len() > 0 && queue.Peek().(*queueItem).isItem {
			item := queue.Pop().(*queueItem)
			if !iter(item.node.unsafeItem().item, item.dist) {
				return false
			}
		}
		last := queue.Pop()
		if last != nil {
			node = (*treeNode)(last.(*queueItem).node)
		} else {
			node = nil
		}
	}
	return true
}

func boxDistRect(a, b *treeNode) float64 {
	var dist float64
	for i := 0; i < len(a.min); i++ {
		var min, max float64
		if a.min[i] > b.min[i] {
			min = a.min[i]
		} else {
			min = b.min[i]
		}
		if a.max[i] < b.max[i] {
			max = a.max[i]
		} else {
			max = b.max[i]
		}
		squared := min - max
		if squared > 0 {
			dist += squared * squared
		}
	}
	return dist
}

func boxDistPoint(point []float64, childBox *treeNode) float64 {
	var dist float64
	for i := 0; i < len(point); i++ {
		d := axisDist(point[i], childBox.min[i], childBox.max[i])
		dist += d * d
	}
	return dist
}

func axisDist(k, min, max float64) float64 {
	if k < min {
		return min - k
	}
	if k <= max {
		return 0
	}
	return k - max
}

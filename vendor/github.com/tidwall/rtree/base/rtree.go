package base

import (
	"math"
	"unsafe"
)

// precalculate infinity
var mathInfNeg = math.Inf(-1)
var mathInfPos = math.Inf(+1)

type treeNode struct {
	min, max []float64
	children []*treeNode
	count    int
	height   int
	leaf     bool
}

func (node *treeNode) unsafeItem() *treeItem {
	return (*treeItem)(unsafe.Pointer(node))
}

func (tr *RTree) createNode(children []*treeNode) *treeNode {
	n := &treeNode{
		height:   1,
		leaf:     true,
		children: make([]*treeNode, tr.maxEntries+1),
	}
	if len(children) > 0 {
		n.count = len(children)
		copy(n.children[:n.count], children)
	}
	n.min = make([]float64, tr.dims)
	n.max = make([]float64, tr.dims)
	for i := 0; i < tr.dims; i++ {
		n.min[i] = mathInfPos
		n.max[i] = mathInfNeg
	}
	return n
}

func (node *treeNode) extend(b *treeNode) {
	for i := 0; i < len(node.min); i++ {
		if b.min[i] < node.min[i] {
			node.min[i] = b.min[i]
		}
		if b.max[i] > node.max[i] {
			node.max[i] = b.max[i]
		}
	}
}

func (node *treeNode) area() float64 {
	area := node.max[0] - node.min[0]
	for i := 1; i < len(node.min); i++ {
		area *= node.max[i] - node.min[i]
	}
	return area
}

func (node *treeNode) enlargedAreaAxis(b *treeNode, axis int) float64 {
	var max, min float64
	if b.max[axis] > node.max[axis] {
		max = b.max[axis]
	} else {
		max = node.max[axis]
	}
	if b.min[axis] < node.min[axis] {
		min = b.min[axis]
	} else {
		min = node.min[axis]
	}
	return max - min
}

func (node *treeNode) enlargedArea(b *treeNode) float64 {
	area := node.enlargedAreaAxis(b, 0)
	for i := 1; i < len(node.min); i++ {
		area *= node.enlargedAreaAxis(b, i)
	}
	return area
}

func (node *treeNode) intersectionAreaAxis(b *treeNode, axis int) float64 {
	var max, min float64
	if node.max[axis] < b.max[axis] {
		max = node.max[axis]
	} else {
		max = b.max[axis]
	}
	if node.min[axis] > b.min[axis] {
		min = node.min[axis]
	} else {
		min = b.min[axis]
	}
	if max > min {
		return max - min
	}
	return 0
}
func (node *treeNode) intersectionArea(b *treeNode) float64 {
	area := node.intersectionAreaAxis(b, 0)
	for i := 1; i < len(node.min); i++ {
		area *= node.intersectionAreaAxis(b, i)
	}
	return area
}
func (node *treeNode) margin() float64 {
	margin := node.max[0] - node.min[0]
	for i := 1; i < len(node.min); i++ {
		margin += node.max[i] - node.min[i]
	}
	return margin
}

type result int

const (
	not        result = 0
	intersects result = 1
	contains   result = 2
)

func (node *treeNode) overlaps(b *treeNode) result {
	for i := 0; i < len(node.min); i++ {
		if b.min[i] > node.max[i] || b.max[i] < node.min[i] {
			return not
		}
		if node.min[i] > b.min[i] || b.max[i] > node.max[i] {
			i++
			for ; i < len(node.min); i++ {
				if b.min[i] > node.max[i] || b.max[i] < node.min[i] {
					return not
				}
			}
			return intersects
		}
	}
	return contains
}

func (node *treeNode) intersects(b *treeNode) bool {
	for i := 0; i < len(node.min); i++ {
		if b.min[i] > node.max[i] || b.max[i] < node.min[i] {
			return false
		}
	}
	return true
}

func (node *treeNode) findItem(item interface{}) int {
	for i := 0; i < node.count; i++ {
		if node.children[i].unsafeItem().item == item {
			return i
		}
	}
	return -1
}

func (node *treeNode) contains(b *treeNode) bool {
	for i := 0; i < len(node.min); i++ {
		if node.min[i] > b.min[i] || b.max[i] > node.max[i] {
			return false
		}
	}
	return true
}

func (node *treeNode) childCount() int {
	if node.leaf {
		return node.count
	}
	var n int
	for i := 0; i < node.count; i++ {
		n += node.children[i].childCount()
	}
	return n
}

type treeItem struct {
	min, max []float64
	item     interface{}
}

func (item *treeItem) unsafeNode() *treeNode {
	return (*treeNode)(unsafe.Pointer(item))
}

// RTree is an R-tree
type RTree struct {
	dims       int
	maxEntries int
	minEntries int
	data       *treeNode // root node
	// resusable fields, these help performance of common mutable operations.
	reuse struct {
		path    []*treeNode // for reinsertion path
		indexes []int       // for remove function
		stack   []int       // for bulk loading
	}
}

// New creates a new R-tree
func New(dims, maxEntries int) *RTree {
	if dims <= 0 {
		panic("invalid dimensions")
	}

	tr := &RTree{}
	tr.dims = dims
	tr.maxEntries = int(math.Max(4, float64(maxEntries)))
	tr.minEntries = int(math.Max(2, math.Ceil(float64(tr.maxEntries)*0.4)))
	tr.data = tr.createNode(nil)
	return tr
}

// Insert inserts an item
func (tr *RTree) Insert(min, max []float64, item interface{}) {
	if len(min) != tr.dims || len(max) != tr.dims {
		panic("invalid dimensions")
	}
	if item == nil {
		panic("nil item")
	}
	bbox := treeNode{min: min, max: max}
	tr.insert(&bbox, item, tr.data.height-1, false)
}

func (tr *RTree) insert(bbox *treeNode, item interface{}, level int, isNode bool) {
	tr.reuse.path = tr.reuse.path[:0]
	node, insertPath := tr.chooseSubtree(bbox, tr.data, level, tr.reuse.path)
	if item == nil {
		// item is only nil when bulk loading a node
		if node.leaf {
			panic("loading node into leaf")
		}
		node.children[node.count] = bbox
		node.count++
	} else {
		ti := &treeItem{min: bbox.min, max: bbox.max, item: item}
		node.children[node.count] = ti.unsafeNode()
		node.count++
	}
	node.extend(bbox)
	for level >= 0 {
		if insertPath[level].count > tr.maxEntries {
			insertPath = tr.split(insertPath, level)
			level--
		} else {
			break
		}
	}
	tr.adjustParentBBoxes(bbox, insertPath, level)
	tr.reuse.path = insertPath
}

func (tr *RTree) adjustParentBBoxes(bbox *treeNode, path []*treeNode, level int) {
	// adjust bboxes along the given tree path
	for i := level; i >= 0; i-- {
		path[i].extend(bbox)
	}
}

func (tr *RTree) chooseSubtree(bbox, node *treeNode, level int, path []*treeNode) (*treeNode, []*treeNode) {
	var targetNode *treeNode
	var area, enlargement, minArea, minEnlargement float64
	for {
		path = append(path, node)
		if node.leaf || len(path)-1 == level {
			break
		}
		minEnlargement = mathInfPos
		minArea = minEnlargement
		for i := 0; i < node.count; i++ {
			child := node.children[i]
			area = child.area()
			enlargement = bbox.enlargedArea(child) - area
			if enlargement < minEnlargement {
				minEnlargement = enlargement
				if area < minArea {
					minArea = area
				}
				targetNode = child
			} else if enlargement == minEnlargement {
				if area < minArea {
					minArea = area
					targetNode = child
				}
			}
		}
		if targetNode != nil {
			node = targetNode
		} else if node.count > 0 {
			node = (*treeNode)(node.children[0])
		} else {
			node = nil
		}
	}
	return node, path
}
func (tr *RTree) split(insertPath []*treeNode, level int) []*treeNode {
	var node = insertPath[level]
	var M = node.count
	var m = tr.minEntries

	tr.chooseSplitAxis(node, m, M)
	splitIndex := tr.chooseSplitIndex(node, m, M)

	spliced := make([]*treeNode, node.count-splitIndex)
	copy(spliced, node.children[splitIndex:])
	node.count = splitIndex

	newNode := tr.createNode(spliced)
	newNode.height = node.height
	newNode.leaf = node.leaf

	tr.calcBBox(node)
	tr.calcBBox(newNode)

	if level != 0 {
		insertPath[level-1].children[insertPath[level-1].count] = newNode
		insertPath[level-1].count++
	} else {
		tr.splitRoot(node, newNode)
	}
	return insertPath
}
func (tr *RTree) chooseSplitIndex(node *treeNode, m, M int) int {
	var i int
	var bbox1, bbox2 *treeNode
	var overlap, area, minOverlap, minArea float64
	var index int

	minArea = mathInfPos
	minOverlap = minArea

	for i = m; i <= M-m; i++ {
		bbox1 = tr.distBBox(node, 0, i, nil)
		bbox2 = tr.distBBox(node, i, M, nil)

		overlap = bbox1.intersectionArea(bbox2)
		area = bbox1.area() + bbox2.area()

		// choose distribution with minimum overlap
		if overlap < minOverlap {
			minOverlap = overlap
			index = i

			if area < minArea {
				minArea = area
			}
		} else if overlap == minOverlap {
			// otherwise choose distribution with minimum area
			if area < minArea {
				minArea = area
				index = i
			}
		}
	}
	return index
}
func (tr *RTree) calcBBox(node *treeNode) {
	tr.distBBox(node, 0, node.count, node)
}
func (tr *RTree) chooseSplitAxis(node *treeNode, m, M int) {
	minMargin := tr.allDistMargin(node, m, M, 0)
	var minAxis int
	for axis := 1; axis < tr.dims; axis++ {
		margin := tr.allDistMargin(node, m, M, axis)
		if margin < minMargin {
			minMargin = margin
			minAxis = axis
		}
	}
	if minAxis < tr.dims {
		tr.sortNodes(node, minAxis)
	}
}
func (tr *RTree) splitRoot(node, newNode *treeNode) {
	tr.data = tr.createNode([]*treeNode{node, newNode})
	tr.data.height = node.height + 1
	tr.data.leaf = false
	tr.calcBBox(tr.data)
}
func (tr *RTree) distBBox(node *treeNode, k, p int, destNode *treeNode) *treeNode {
	if destNode == nil {
		destNode = tr.createNode(nil)
	} else {
		for i := 0; i < tr.dims; i++ {
			destNode.min[i] = mathInfPos
			destNode.max[i] = mathInfNeg
		}
	}
	for i := k; i < p; i++ {
		if node.leaf {
			destNode.extend(node.children[i])
		} else {
			destNode.extend((*treeNode)(node.children[i]))
		}
	}
	return destNode
}
func (tr *RTree) allDistMargin(node *treeNode, m, M int, axis int) float64 {
	tr.sortNodes(node, axis)

	var leftBBox = tr.distBBox(node, 0, m, nil)
	var rightBBox = tr.distBBox(node, M-m, M, nil)
	var margin = leftBBox.margin() + rightBBox.margin()

	var i int

	if node.leaf {
		for i = m; i < M-m; i++ {
			leftBBox.extend(node.children[i])
			margin += leftBBox.margin()
		}
		for i = M - m - 1; i >= m; i-- {
			leftBBox.extend(node.children[i])
			margin += rightBBox.margin()
		}
	} else {
		for i = m; i < M-m; i++ {
			child := (*treeNode)(node.children[i])
			leftBBox.extend(child)
			margin += leftBBox.margin()
		}
		for i = M - m - 1; i >= m; i-- {
			child := (*treeNode)(node.children[i])
			leftBBox.extend(child)
			margin += rightBBox.margin()
		}
	}
	return margin
}
func (tr *RTree) sortNodes(node *treeNode, axis int) {
	sortByAxis(node.children[:node.count], axis)
}

func sortByAxis(items []*treeNode, axis int) {
	if len(items) < 2 {
		return
	}
	left, right := 0, len(items)-1
	pivotIndex := len(items) / 2
	items[pivotIndex], items[right] = items[right], items[pivotIndex]
	for i := range items {
		if items[i].min[axis] < items[right].min[axis] {
			items[i], items[left] = items[left], items[i]
			left++
		}
	}
	items[left], items[right] = items[right], items[left]
	sortByAxis(items[:left], axis)
	sortByAxis(items[left+1:], axis)
}

// Search searches the tree for items in the input rectangle
func (tr *RTree) Search(min, max []float64, iter func(item interface{}) bool) bool {
	bbox := &treeNode{min: min, max: max}
	if !tr.data.intersects(bbox) {
		return true
	}
	return tr.search(tr.data, bbox, iter)
}

func (tr *RTree) search(node, bbox *treeNode, iter func(item interface{}) bool) bool {
	if node.leaf {
		for i := 0; i < node.count; i++ {
			if bbox.intersects(node.children[i]) {
				if !iter(node.children[i].unsafeItem().item) {
					return false
				}
			}
		}
	} else {
		for i := 0; i < node.count; i++ {
			r := bbox.overlaps(node.children[i])
			if r == intersects {
				if !tr.search(node.children[i], bbox, iter) {
					return false
				}
			} else if r == contains {
				if !scan(node.children[i], iter) {
					return false
				}
			}
		}
	}
	return true
}

func (tr *RTree) IsEmpty() bool {
	empty := true
	tr.Scan(func(item interface{}) bool {
		empty = false
		return false
	})
	return empty
}

// Remove removes an item from the R-tree.
func (tr *RTree) Remove(min, max []float64, item interface{}) {
	bbox := &treeNode{min: min, max: max}
	tr.remove(bbox, item)
}

func (tr *RTree) remove(bbox *treeNode, item interface{}) {
	path := tr.reuse.path[:0]
	indexes := tr.reuse.indexes[:0]

	var node = tr.data
	var i int
	var parent *treeNode
	var index int
	var goingUp bool

	for node != nil || len(path) != 0 {
		if node == nil {
			node = path[len(path)-1]
			path = path[:len(path)-1]
			if len(path) == 0 {
				parent = nil
			} else {
				parent = path[len(path)-1]
			}
			i = indexes[len(indexes)-1]
			indexes = indexes[:len(indexes)-1]
			goingUp = true
		}

		if node.leaf {
			index = node.findItem(item)
			if index != -1 {
				// item found, remove the item and condense tree upwards
				copy(node.children[index:], node.children[index+1:])
				node.children[node.count-1] = nil
				node.count--
				path = append(path, node)
				tr.condense(path)
				goto done
			}
		}
		if !goingUp && !node.leaf && node.contains(bbox) { // go down
			path = append(path, node)
			indexes = append(indexes, i)
			i = 0
			parent = node
			node = (*treeNode)(node.children[0])
		} else if parent != nil { // go right
			i++
			if i == parent.count {
				node = nil
			} else {
				node = (*treeNode)(parent.children[i])
			}
			goingUp = false
		} else {
			node = nil
		}
	}
done:
	tr.reuse.path = path
	tr.reuse.indexes = indexes
	return
}
func (tr *RTree) condense(path []*treeNode) {
	// go through the path, removing empty nodes and updating bboxes
	var siblings []*treeNode
	for i := len(path) - 1; i >= 0; i-- {
		if path[i].count == 0 {
			if i > 0 {
				siblings = path[i-1].children[:path[i-1].count]
				index := -1
				for j := 0; j < len(siblings); j++ {
					if siblings[j] == path[i] {
						index = j
						break
					}
				}
				copy(siblings[index:], siblings[index+1:])
				siblings[len(siblings)-1] = nil
				path[i-1].count--
				//siblings = siblings[:len(siblings)-1]
				//path[i-1].children = siblings
			} else {
				tr.data = tr.createNode(nil) // clear tree
			}
		} else {
			tr.calcBBox(path[i])
		}
	}
}

// Count returns the number of items in the R-tree.
func (tr *RTree) Count() int {
	return tr.data.childCount()
}

// Traverse iterates over the entire R-tree and includes all nodes and items.
func (tr *RTree) Traverse(iter func(min, max []float64, level int, item interface{}) bool) bool {
	return tr.traverse(tr.data, iter)
}

func (tr *RTree) traverse(node *treeNode, iter func(min, max []float64, level int, item interface{}) bool) bool {
	if !iter(node.min, node.max, int(node.height), nil) {
		return false
	}
	if node.leaf {
		for i := 0; i < node.count; i++ {
			child := node.children[i]
			if !iter(child.min, child.max, 0, child.unsafeItem().item) {
				return false
			}
		}
	} else {
		for i := 0; i < node.count; i++ {
			child := node.children[i]
			if !tr.traverse(child, iter) {
				return false
			}
		}
	}
	return true
}

// Scan iterates over the entire R-tree
func (tr *RTree) Scan(iter func(item interface{}) bool) bool {
	return scan(tr.data, iter)
}

func scan(node *treeNode, iter func(item interface{}) bool) bool {
	if node.leaf {
		for i := 0; i < node.count; i++ {
			child := node.children[i]
			if !iter(child.unsafeItem().item) {
				return false
			}
		}
	} else {
		for i := 0; i < node.count; i++ {
			child := node.children[i]
			if !scan(child, iter) {
				return false
			}
		}
	}
	return true
}

// Bounds returns the bounding box of the entire R-tree
func (tr *RTree) Bounds() (min, max []float64) {
	if tr.data.count > 0 {
		return tr.data.min, tr.data.max
	}
	return make([]float64, tr.dims), make([]float64, tr.dims)
}

// Complexity returns the complexity of the R-tree. The higher the value, the
// more complex the tree. The value of 1 is the lowest.
func (tr *RTree) Complexity() float64 {
	var nodeCount int
	var itemCount int
	tr.Traverse(func(_, _ []float64, level int, _ interface{}) bool {
		if level == 0 {
			itemCount++
		} else {
			nodeCount++
		}
		return true
	})
	return float64(tr.maxEntries*nodeCount) / float64(itemCount)
}

RTree implementation for Go
===========================

[![Build Status](https://travis-ci.org/tidwall/rtree.svg?branch=master)](https://travis-ci.org/tidwall/rtree)
[![GoDoc](https://godoc.org/github.com/tidwall/rtree?status.svg)](https://godoc.org/github.com/tidwall/rtree)

This package provides an in-memory R-Tree implementation for Go, useful as a spatial data structure.
It has support for 1-20 dimensions, and can store and search multidimensions interchangably in the same tree.

Authors
-------
* 1983 Original algorithm and test code by Antonin Guttman and Michael Stonebraker, UC Berkely
* 1994 ANCI C ported from original test code by Melinda Green 
* 1995 Sphere volume fix for degeneracy problem submitted by Paul Brook
* 2004 Templated C++ port by Greg Douglas
* 2016 Go port by Josh Baker
* 2018 Added kNN and merged in some of the RBush logic by Vladimir Agafonkin

License
-------
RTree source code is available under the MIT License.


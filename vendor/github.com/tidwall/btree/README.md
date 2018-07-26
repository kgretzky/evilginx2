BTree implementation for Go
===========================

![Travis CI Build Status](https://api.travis-ci.org/tidwall/btree.svg?branch=master)
[![GoDoc](https://godoc.org/github.com/tidwall/btree?status.svg)](https://godoc.org/github.com/tidwall/btree)

This package provides an in-memory B-Tree implementation for Go, useful as
an ordered, mutable data structure.

This is a fork of the wonderful [google/btree](https://github.com/google/btree) package. It's has all the same great features and adds a few more.

- Descend* functions for iterating backwards.
- Iteration performance boost.
- User defined context.

User defined context
--------------------
This is a great new feature that allows for entering the same item into multiple B-trees, and each B-tree have a different ordering formula.

For example:

```go
package main

import (
	"fmt"

	"github.com/tidwall/btree"
)

type Item struct {
	Key, Val string
}

func (i1 *Item) Less(item btree.Item, ctx interface{}) bool {
	i2 := item.(*Item)
	switch tag := ctx.(type) {
	case string:
		if tag == "vals" {
			if i1.Val < i2.Val {
				return true
			} else if i1.Val > i2.Val {
				return false
			}
			// Both vals are equal so we should fall though
			// and let the key comparison take over.
		}
	}
	return i1.Key < i2.Key
}

func main() {

	// Create a tree for keys and a tree for values.
	// The "keys" tree will be sorted on the Keys field.
	// The "values" tree will be sorted on the Values field.
	keys := btree.New(16, "keys")
	vals := btree.New(16, "vals")

	// Create some items.
	users := []*Item{
		&Item{Key: "user:1", Val: "Jane"},
		&Item{Key: "user:2", Val: "Andy"},
		&Item{Key: "user:3", Val: "Steve"},
		&Item{Key: "user:4", Val: "Andrea"},
		&Item{Key: "user:5", Val: "Janet"},
		&Item{Key: "user:6", Val: "Andy"},
	}

	// Insert each user into both trees
	for _, user := range users {
		keys.ReplaceOrInsert(user)
		vals.ReplaceOrInsert(user)
	}

	// Iterate over each user in the key tree
	keys.Ascend(func(item btree.Item) bool {
		kvi := item.(*Item)
		fmt.Printf("%s %s\n", kvi.Key, kvi.Val)
		return true
	})

	fmt.Printf("\n")
	// Iterate over each user in the val tree
	vals.Ascend(func(item btree.Item) bool {
		kvi := item.(*Item)
		fmt.Printf("%s %s\n", kvi.Key, kvi.Val)
		return true
	})
}

// Should see the results
/*
user:1 Jane
user:2 Andy
user:3 Steve
user:4 Andrea
user:5 Janet
user:6 Andy

user:4 Andrea
user:2 Andy
user:6 Andy
user:1 Jane
user:3 Steve
*/
```

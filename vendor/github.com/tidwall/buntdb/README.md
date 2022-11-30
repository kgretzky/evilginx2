<p align="center">
<img
    src="logo.png"
    width="307" height="150" border="0" alt="BuntDB">
<br>
<a href="https://godoc.org/github.com/tidwall/buntdb"><img src="https://img.shields.io/badge/go-documentation-blue.svg?style=flat-square" alt="Godoc"></a>
<a href="https://github.com/tidwall/buntdb/blob/master/LICENSE"><img src="https://img.shields.io/github/license/tidwall/buntdb.svg?style=flat-square" alt="LICENSE"></a>
</p>

BuntDB is a low-level, in-memory, key/value store in pure Go.
It persists to disk, is ACID compliant, and uses locking for multiple
readers and a single writer. It supports custom indexes and geospatial
data. It's ideal for projects that need a dependable database and favor
speed over data size.

Features
========

- In-memory database for [fast reads and writes](#performance)
- Embeddable with a [simple API](https://godoc.org/github.com/tidwall/buntdb)
- [Spatial indexing](#spatial-indexes) for up to 20 dimensions; Useful for Geospatial data
- Index fields inside [JSON](#json-indexes) documents
- [Collate i18n Indexes](#collate-i18n-indexes) using the optional [collate package](https://github.com/tidwall/collate)
- Create [custom indexes](#custom-indexes) for any data type
- Support for [multi value indexes](#multi-value-index); Similar to a SQL multi column index
- [Built-in types](#built-in-types) that are easy to get up & running; String, Uint, Int, Float
- Flexible [iteration](#iterating) of data; ascending, descending, and ranges
- [Durable append-only file](#append-only-file) format for persistence
- Option to evict old items with an [expiration](#data-expiration) TTL
- ACID semantics with locking [transactions](#transactions) that support rollbacks


Getting Started
===============

## Installing

To start using BuntDB, install Go and run `go get`:

```sh
$ go get -u github.com/tidwall/buntdb
```

This will retrieve the library.


## Opening a database

The primary object in BuntDB is a `DB`. To open or create your
database, use the `buntdb.Open()` function:

```go
package main

import (
	"log"

	"github.com/tidwall/buntdb"
)

func main() {
	// Open the data.db file. It will be created if it doesn't exist.
	db, err := buntdb.Open("data.db")
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	...
}
```

It's also possible to open a database that does not persist to disk by using `:memory:` as the path of the file.

```go
buntdb.Open(":memory:") // Open a file that does not persist to disk.
```

## Transactions
All reads and writes must be performed from inside a transaction. BuntDB can have one write transaction opened at a time, but can have many concurrent read transactions. Each transaction maintains a stable view of the database. In other words, once a transaction has begun, the data for that transaction cannot be changed by other transactions.

Transactions run in a function that exposes a `Tx` object, which represents the transaction state. While inside a transaction, all database operations should be performed using this object. You should never access the origin `DB` object while inside a transaction. Doing so may have side-effects, such as blocking your application.

When a transaction fails, it will roll back, and revert all changes that occurred to the database during that transaction. There's a single return value that you can use to close the transaction. For read/write transactions, returning an error this way will force the transaction to roll back. When a read/write transaction succeeds all changes are persisted to disk.

### Read-only Transactions
A read-only transaction should be used when you don't need to make changes to the data. The advantage of a read-only transaction is that there can be many running concurrently.

```go
err := db.View(func(tx *buntdb.Tx) error {
	...
	return nil
})
```

### Read/write Transactions
A read/write transaction is used when you need to make changes to your data. There can only be one read/write transaction running at a time. So make sure you close it as soon as you are done with it.

```go
err := db.Update(func(tx *buntdb.Tx) error {
	...
	return nil
})
```

## Setting and getting key/values

To set a value you must open a read/write transaction:

```go
err := db.Update(func(tx *buntdb.Tx) error {
	_, _, err := tx.Set("mykey", "myvalue", nil)
	return err
})
```


To get the value:

```go
err := db.View(func(tx *buntdb.Tx) error {
	val, err := tx.Get("mykey")
	if err != nil{
		return err
	}
	fmt.Printf("value is %s\n", val)
	return nil
})
```

Getting non-existent values will cause an `ErrNotFound` error.

### Iterating
All keys/value pairs are ordered in the database by the key. To iterate over the keys:

```go
err := db.View(func(tx *buntdb.Tx) error {
	err := tx.Ascend("", func(key, value string) bool {
		fmt.Printf("key: %s, value: %s\n", key, value)
		return true // continue iteration
	})
	return err
})
```

There is also `AscendGreaterOrEqual`, `AscendLessThan`, `AscendRange`, `AscendEqual`, `Descend`, `DescendLessOrEqual`, `DescendGreaterThan`, `DescendRange`, and `DescendEqual`. Please see the [documentation](https://godoc.org/github.com/tidwall/buntdb) for more information on these functions.


## Custom Indexes
Initially all data is stored in a single [B-tree](https://en.wikipedia.org/wiki/B-tree) with each item having one key and one value. All of these items are ordered by the key. This is great for quickly getting a value from a key or [iterating](#iterating) over the keys. Feel free to peruse the [B-tree implementation](https://github.com/tidwall/btree).

You can also create custom indexes that allow for ordering and [iterating](#iterating) over values. A custom index also uses a B-tree, but it's more flexible because it allows for custom ordering.

For example, let's say you want to create an index for ordering names:

```go
db.CreateIndex("names", "*", buntdb.IndexString)
```

This will create an index named `names` which stores and sorts all values. The second parameter is a pattern that is used to filter on keys. A `*` wildcard argument means that we want to accept all keys. `IndexString` is a built-in function that performs case-insensitive ordering on the values

Now you can add various names:

```go
db.Update(func(tx *buntdb.Tx) error {
	tx.Set("user:0:name", "tom", nil)
	tx.Set("user:1:name", "Randi", nil)
	tx.Set("user:2:name", "jane", nil)
	tx.Set("user:4:name", "Janet", nil)
	tx.Set("user:5:name", "Paula", nil)
	tx.Set("user:6:name", "peter", nil)
	tx.Set("user:7:name", "Terri", nil)
	return nil
})
```

Finally you can iterate over the index:

```go
db.View(func(tx *buntdb.Tx) error {
	tx.Ascend("names", func(key, val string) bool {
	fmt.Printf(buf, "%s %s\n", key, val)
		return true
	})
	return nil
})
```
The output should be:
```
user:2:name jane
user:4:name Janet
user:5:name Paula
user:6:name peter
user:1:name Randi
user:7:name Terri
user:0:name tom
```

The pattern parameter can be used to filter on keys like this:

```go
db.CreateIndex("names", "user:*", buntdb.IndexString)
```

Now only items with keys that have the prefix `user:` will be added to the `names` index.


### Built-in types
Along with `IndexString`, there is also `IndexInt`, `IndexUint`, and `IndexFloat`.
These are built-in types for indexing. You can choose to use these or create your own.

So to create an index that is numerically ordered on an age key, we could use:

```go
db.CreateIndex("ages", "user:*:age", buntdb.IndexInt)
```

And then add values:

```go
db.Update(func(tx *buntdb.Tx) error {
	tx.Set("user:0:age", "35", nil)
	tx.Set("user:1:age", "49", nil)
	tx.Set("user:2:age", "13", nil)
	tx.Set("user:4:age", "63", nil)
	tx.Set("user:5:age", "8", nil)
	tx.Set("user:6:age", "3", nil)
	tx.Set("user:7:age", "16", nil)
	return nil
})
```

```go
db.View(func(tx *buntdb.Tx) error {
	tx.Ascend("ages", func(key, val string) bool {
	fmt.Printf(buf, "%s %s\n", key, val)
		return true
	})
	return nil
})
```

The output should be:
```
user:6:age 3
user:5:age 8
user:2:age 13
user:7:age 16
user:0:age 35
user:1:age 49
user:4:age 63
```

## Spatial Indexes
BuntDB has support for spatial indexes by storing rectangles in an [R-tree](https://en.wikipedia.org/wiki/R-tree). An R-tree is organized in a similar manner as a [B-tree](https://en.wikipedia.org/wiki/B-tree), and both are balanced trees. But, an R-tree is special because it can operate on data that is in multiple dimensions. This is super handy for Geospatial applications.

To create a spatial index use the `CreateSpatialIndex` function:

```go
db.CreateSpatialIndex("fleet", "fleet:*:pos", buntdb.IndexRect)
```

Then `IndexRect` is a built-in function that converts rect strings to a format that the R-tree can use. It's easy to use this function out of the box, but you might find it better to create a custom one that renders from a different format, such as [Well-known text](https://en.wikipedia.org/wiki/Well-known_text) or [GeoJSON](http://geojson.org/).

To add some lon,lat points to the `fleet` index:

```go
db.Update(func(tx *buntdb.Tx) error {
	tx.Set("fleet:0:pos", "[-115.567 33.532]", nil)
	tx.Set("fleet:1:pos", "[-116.671 35.735]", nil)
	tx.Set("fleet:2:pos", "[-113.902 31.234]", nil)
	return nil
})
```

And then you can run the `Intersects` function on the index:

```go
db.View(func(tx *buntdb.Tx) error {
	tx.Intersects("fleet", "[-117 30],[-112 36]", func(key, val string) bool {
		...
		return true
	})
	return nil
})
```

This will get all three positions.

### k-Nearest Neighbors

Use the `Nearby` function to get all the positions in order of nearest to farthest :

```go
db.View(func(tx *buntdb.Tx) error {
	tx.Nearby("fleet", "[-113 33]", func(key, val string, dist float64) bool {
		...
		return true
	})
	return nil
})
```

### Spatial bracket syntax

The bracket syntax `[-117 30],[-112 36]` is unique to BuntDB, and it's how the built-in rectangles are processed. But, you are not limited to this syntax. Whatever Rect function you choose to use during `CreateSpatialIndex` will be used to process the parameter, in this case it's `IndexRect`.

- **2D rectangle:** `[10 15],[20 25]`
*Min XY: "10x15", Max XY: "20x25"*

- **3D rectangle:** `[10 15 12],[20 25 18]`
*Min XYZ: "10x15x12", Max XYZ: "20x25x18"*

- **2D point:** `[10 15]`
*XY: "10x15"*

- **LonLat point:** `[-112.2693 33.5123]`
*LatLon: "33.5123 -112.2693"*

- **LonLat bounding box:** `[-112.26 33.51],[-112.18 33.67]`
*Min LatLon: "33.51 -112.26", Max LatLon: "33.67 -112.18"*

**Notice:** The longitude is the Y axis and is on the left, and latitude is the X axis and is on the right.

You can also represent `Infinity` by using `-inf` and `+inf`.
For example, you might have the following points (`[X Y M]` where XY is a point and M is a timestamp):
```
[3 9 1]
[3 8 2]
[4 8 3]
[4 7 4]
[5 7 5]
[5 6 6]
```

You can then do a search for all points with `M` between 2-4 by calling `Intersects`.

```go
tx.Intersects("points", "[-inf -inf 2],[+inf +inf 4]", func(key, val string) bool {
	println(val)
	return true
})
```

Which will return:

```
[3 8 2]
[4 8 3]
[4 7 4]
```

## JSON Indexes
Indexes can be created on individual fields inside JSON documents. BuntDB uses [GJSON](https://github.com/tidwall/gjson) under the hood.

For example:

```go
package main

import (
	"fmt"

	"github.com/tidwall/buntdb"
)

func main() {
	db, _ := buntdb.Open(":memory:")
	db.CreateIndex("last_name", "*", buntdb.IndexJSON("name.last"))
	db.CreateIndex("age", "*", buntdb.IndexJSON("age"))
	db.Update(func(tx *buntdb.Tx) error {
		tx.Set("1", `{"name":{"first":"Tom","last":"Johnson"},"age":38}`, nil)
		tx.Set("2", `{"name":{"first":"Janet","last":"Prichard"},"age":47}`, nil)
		tx.Set("3", `{"name":{"first":"Carol","last":"Anderson"},"age":52}`, nil)
		tx.Set("4", `{"name":{"first":"Alan","last":"Cooper"},"age":28}`, nil)
		return nil
	})
	db.View(func(tx *buntdb.Tx) error {
		fmt.Println("Order by last name")
		tx.Ascend("last_name", func(key, value string) bool {
			fmt.Printf("%s: %s\n", key, value)
			return true
		})
		fmt.Println("Order by age")
		tx.Ascend("age", func(key, value string) bool {
			fmt.Printf("%s: %s\n", key, value)
			return true
		})
		fmt.Println("Order by age range 30-50")
		tx.AscendRange("age", `{"age":30}`, `{"age":50}`, func(key, value string) bool {
			fmt.Printf("%s: %s\n", key, value)
			return true
		})
		return nil
	})
}
```

Results:

```
Order by last name
3: {"name":{"first":"Carol","last":"Anderson"},"age":52}
4: {"name":{"first":"Alan","last":"Cooper"},"age":28}
1: {"name":{"first":"Tom","last":"Johnson"},"age":38}
2: {"name":{"first":"Janet","last":"Prichard"},"age":47}

Order by age
4: {"name":{"first":"Alan","last":"Cooper"},"age":28}
1: {"name":{"first":"Tom","last":"Johnson"},"age":38}
2: {"name":{"first":"Janet","last":"Prichard"},"age":47}
3: {"name":{"first":"Carol","last":"Anderson"},"age":52}

Order by age range 30-50
1: {"name":{"first":"Tom","last":"Johnson"},"age":38}
2: {"name":{"first":"Janet","last":"Prichard"},"age":47}
```

## Multi Value Index
With BuntDB it's possible to join multiple values on a single index.
This is similar to a [multi column index](http://dev.mysql.com/doc/refman/5.7/en/multiple-column-indexes.html) in a traditional SQL database.

In this example we are creating a multi value index on "name.last" and "age":

```go
db, _ := buntdb.Open(":memory:")
db.CreateIndex("last_name_age", "*", buntdb.IndexJSON("name.last"), buntdb.IndexJSON("age"))
db.Update(func(tx *buntdb.Tx) error {
	tx.Set("1", `{"name":{"first":"Tom","last":"Johnson"},"age":38}`, nil)
	tx.Set("2", `{"name":{"first":"Janet","last":"Prichard"},"age":47}`, nil)
	tx.Set("3", `{"name":{"first":"Carol","last":"Anderson"},"age":52}`, nil)
	tx.Set("4", `{"name":{"first":"Alan","last":"Cooper"},"age":28}`, nil)
	tx.Set("5", `{"name":{"first":"Sam","last":"Anderson"},"age":51}`, nil)
	tx.Set("6", `{"name":{"first":"Melinda","last":"Prichard"},"age":44}`, nil)
	return nil
})
db.View(func(tx *buntdb.Tx) error {
	tx.Ascend("last_name_age", func(key, value string) bool {
		fmt.Printf("%s: %s\n", key, value)
		return true
	})
	return nil
})

// Output:
// 5: {"name":{"first":"Sam","last":"Anderson"},"age":51}
// 3: {"name":{"first":"Carol","last":"Anderson"},"age":52}
// 4: {"name":{"first":"Alan","last":"Cooper"},"age":28}
// 1: {"name":{"first":"Tom","last":"Johnson"},"age":38}
// 6: {"name":{"first":"Melinda","last":"Prichard"},"age":44}
// 2: {"name":{"first":"Janet","last":"Prichard"},"age":47}
```

## Descending Ordered Index
Any index can be put in descending order by wrapping it's less function with `buntdb.Desc`.

```go
db.CreateIndex("last_name_age", "*",
    buntdb.IndexJSON("name.last"),
    buntdb.Desc(buntdb.IndexJSON("age")),
)
```

This will create a multi value index where the last name is ascending and the age is descending.

## Collate i18n Indexes

Using the external [collate package](https://github.com/tidwall/collate) it's possible to create
indexes that are sorted by the specified language. This is similar to the [SQL COLLATE keyword](https://msdn.microsoft.com/en-us/library/ms174596.aspx) found in traditional databases.

To install:

```
go get -u github.com/tidwall/collate
```

For example:

```go
import "github.com/tidwall/collate"

// To sort case-insensitive in French.
db.CreateIndex("name", "*", collate.IndexString("FRENCH_CI"))

// To specify that numbers should sort numerically ("2" < "12")
// and use a comma to represent a decimal point.
db.CreateIndex("amount", "*", collate.IndexString("FRENCH_NUM"))
```

There's also support for Collation on JSON indexes:

```go
db.CreateIndex("last_name", "*", collate.IndexJSON("CHINESE_CI", "name.last"))
```

Check out the [collate project](https://github.com/tidwall/collate) for more information.

## Data Expiration
Items can be automatically evicted by using the `SetOptions` object in the `Set` function to set a `TTL`.

```go
db.Update(func(tx *buntdb.Tx) error {
	tx.Set("mykey", "myval", &buntdb.SetOptions{Expires:true, TTL:time.Second})
	return nil
})
```

Now `mykey` will automatically be deleted after one second. You can remove the TTL by setting the value again with the same key/value, but with the options parameter set to nil.

## Delete while iterating
BuntDB does not currently support deleting a key while in the process of iterating.
As a workaround you'll need to delete keys following the completion of the iterator.

```go
var delkeys []string
tx.AscendKeys("object:*", func(k, v string) bool {
	if someCondition(k) == true {
		delkeys = append(delkeys, k)
	}
	return true // continue
})
for _, k := range delkeys {
	if _, err = tx.Delete(k); err != nil {
		return err
	}
}
```

## Append-only File

BuntDB uses an AOF (append-only file) which is a log of all database changes that occur from operations like `Set()` and `Delete()`.

The format of this file looks like:
```
set key:1 value1
set key:2 value2
set key:1 value3
del key:2
...
```

When the database opens again, it will read back the aof file and process each command in exact order.
This read process happens one time when the database opens.
From there on the file is only appended.

As you may guess this log file can grow large over time.
There's a background routine that automatically shrinks the log file when it gets too large.
There is also a `Shrink()` function which will rewrite the aof file so that it contains only the items in the database.
The shrink operation does not lock up the database so read and write transactions can continue while shrinking is in process.

### Durability and fsync

By default BuntDB executes an `fsync` once every second on the [aof file](#append-only-file). Which simply means that there's a chance that up to one second of data might be lost. If you need higher durability then there's an optional database config setting `Config.SyncPolicy` which can be set to `Always`.

The `Config.SyncPolicy` has the following options:

- `Never` - fsync is managed by the operating system, less safe
- `EverySecond` - fsync every second, fast and safer, this is the default
- `Always` - fsync after every write, very durable, slower

## Config

Here are some configuration options that can be use to change various behaviors of the database.

- **SyncPolicy** adjusts how often the data is synced to disk. This value can be Never, EverySecond, or Always. Default is EverySecond.
- **AutoShrinkPercentage** is used by the background process to trigger a shrink of the aof file when the size of the file is larger than the percentage of the result of the previous shrunk file. For example, if this value is 100, and the last shrink process resulted in a 100mb file, then the new aof file must be 200mb before a shrink is triggered. Default is 100.
- **AutoShrinkMinSize** defines the minimum size of the aof file before an automatic shrink can occur. Default is 32MB.
- **AutoShrinkDisabled** turns off automatic background shrinking. Default is false.

To update the configuration you should call `ReadConfig` followed by `SetConfig`. For example:

```go

var config buntdb.Config
if err := db.ReadConfig(&config); err != nil{
	log.Fatal(err)
}
if err := db.SetConfig(config); err != nil{
	log.Fatal(err)
}
```

## Performance

How fast is BuntDB?

Here are some example [benchmarks](https://github.com/tidwall/raft-buntdb#raftstore-performance-comparison) when using BuntDB in a Raft Store implementation.

You can also run the standard Go benchmark tool from the project root directory:

```
go test --bench=.
```

### BuntDB-Benchmark

There's a [custom utility](https://github.com/tidwall/buntdb-benchmark) that was created specifically for benchmarking BuntDB.

*These are the results from running the benchmarks on a MacBook Pro 15" 2.8 GHz Intel Core i7:*

```
$ buntdb-benchmark -q
GET: 4609604.74 operations per second
SET: 248500.33 operations per second
ASCEND_100: 2268998.79 operations per second
ASCEND_200: 1178388.14 operations per second
ASCEND_400: 679134.20 operations per second
ASCEND_800: 348445.55 operations per second
DESCEND_100: 2313821.69 operations per second
DESCEND_200: 1292738.38 operations per second
DESCEND_400: 675258.76 operations per second
DESCEND_800: 337481.67 operations per second
SPATIAL_SET: 134824.60 operations per second
SPATIAL_INTERSECTS_100: 939491.47 operations per second
SPATIAL_INTERSECTS_200: 561590.40 operations per second
SPATIAL_INTERSECTS_400: 306951.15 operations per second
SPATIAL_INTERSECTS_800: 159673.91 operations per second
```

To install this utility:

```
go get github.com/tidwall/buntdb-benchmark
```



## Contact
Josh Baker [@tidwall](http://twitter.com/tidwall)

## License

BuntDB source code is available under the MIT [License](/LICENSE).

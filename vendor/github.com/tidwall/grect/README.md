GRECT
====

Quickly get the outer rectangle for GeoJSON, WKT, WKB.

```go
	r := grect.Get(`{
      "type": "Polygon",
      "coordinates": [
        [ [100.0, 0.0], [101.0, 0.0], [101.0, 1.0],
          [100.0, 1.0], [100.0, 0.0] ]
        ]
    }`)
	fmt.Printf("%v %v\n", r.Min, r.Max)
	// Output:
	// [100 0] [101 1]
```

## Contact
Josh Baker [@tidwall](http://twitter.com/tidwall)

## License

GRECT source code is available under the MIT [License](/LICENSE).


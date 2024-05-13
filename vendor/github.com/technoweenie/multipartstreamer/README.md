# multipartstreamer

Package multipartstreamer helps you encode large files in MIME multipart format
without reading the entire content into memory.  It uses io.MultiReader to
combine an inner multipart.Reader with a file handle.

```go
package main

import (
  "github.com/technoweenie/multipartstreamer.go"
  "net/http"
)

func main() {
  ms := multipartstreamer.New()

  ms.WriteFields(map[string]string{
    "key":			"some-key",
    "AWSAccessKeyId":	"ABCDEF",
    "acl":			"some-acl",
  })

  // Add any io.Reader to the multipart.Reader.
  ms.WriteReader("file", "filename", some_ioReader, size)

  // Shortcut for adding local file.
  ms.WriteFile("file", "path/to/file")

  req, _ := http.NewRequest("POST", "someurl", nil)
  ms.SetupRequest(req)

  res, _ := http.DefaultClient.Do(req)
}
```

One limitation: You can only write a single file.

## TODO

* Multiple files?

## Credits

Heavily inspired by James

https://groups.google.com/forum/?fromgroups=#!topic/golang-nuts/Zjg5l4nKcQ0

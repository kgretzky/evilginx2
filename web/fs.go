package web

import (
	"embed"
	"net/http"
)

//go:embed *
var webAssets embed.FS

// GetWebAssets returns a http.FileSystem for the embedded web assets.
func GetWebAssets() http.FileSystem {
	return http.FS(webAssets)
}

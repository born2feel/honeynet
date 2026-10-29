// Package web embeds the built dashboard (web/dist) into the Go binary, so
// the whole honeypot ships as one file. Run `npm run build` before `go build`;
// without it the binary still works and the dashboard URL explains what to do.
package web

import (
	"embed"
	"io/fs"
)

//go:embed all:dist
var dist embed.FS

// Dist returns the dashboard files rooted at dist/.
func Dist() fs.FS {
	sub, err := fs.Sub(dist, "dist")
	if err != nil {
		panic(err)
	}
	return sub
}

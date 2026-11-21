// Package web embeds the single-page UI (web/ui) into the binary. There is no
// build step: the files under ui/ are served as written.
package web

import (
	"embed"
	"io/fs"
)

//go:embed ui/index.html ui/*.js ui/*.css ui/*.svg ui/brand ui/lib ui/screens ui/help
var files embed.FS

// UI returns the ui/ directory as the filesystem root.
func UI() fs.FS {
	sub, err := fs.Sub(files, "ui")
	if err != nil {
		panic(err) // the embed pattern guarantees ui/ exists
	}
	return sub
}

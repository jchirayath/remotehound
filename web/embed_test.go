// @feature:overview
package web

import (
	"io/fs"
	"regexp"
	"testing"
)

// Every /ui/... file the page links to (icons, scripts, styles) is in the binary.
// The embed pattern lists file types, so a new kind (e.g. favicon.ico) is easy to forget.
func TestIndexLinksAreEmbedded(t *testing.T) {
	ui := UI()
	page, err := fs.ReadFile(ui, "index.html")
	if err != nil {
		t.Fatal(err)
	}
	refs := regexp.MustCompile(`(?:href|src)="/ui/([^"?#]+)"`).FindAllSubmatch(page, -1)
	if len(refs) < 3 {
		t.Fatalf("found only %d /ui/ references in index.html — has the page changed shape?", len(refs))
	}
	for _, m := range refs {
		if _, err := fs.Stat(ui, string(m[1])); err != nil {
			t.Errorf("index.html links /ui/%s, which is not embedded (web/embed.go pattern)", m[1])
		}
	}
}

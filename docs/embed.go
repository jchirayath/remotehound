// Package docs embeds the user documentation (docs/user/*.md) so the in-app
// help panel can render it (HELP-6). Developer docs are not embedded.
package docs

import "embed"

// User holds user/*.md.
//
//go:embed user
var User embed.FS

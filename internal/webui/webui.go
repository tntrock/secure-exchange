// Package webui serves the embedded single-page frontend (built into dist by `npm run build` in web/).
package webui

import (
	"embed"
	"io/fs"
	"net/http"
	"path"
	"strings"
)

//go:embed all:dist
var distFS embed.FS

// Handler serves static assets from the embedded build; unknown paths fall back to index.html
// so client-side routes work.
func Handler() http.Handler {
	sub, _ := fs.Sub(distFS, "dist")
	return newHandler(sub)
}

func newHandler(fsys fs.FS) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		name := strings.TrimPrefix(path.Clean(r.URL.Path), "/")
		if name == "" {
			name = "index.html"
		}
		if st, err := fs.Stat(fsys, name); err != nil || st.IsDir() {
			name = "index.html" // SPA fallback
		}
		if _, err := fs.Stat(fsys, name); err != nil {
			http.Error(w, "frontend not built (run npm run build in web/)", http.StatusNotFound)
			return
		}
		if name == "index.html" {
			w.Header().Set("Cache-Control", "no-cache")
		}
		http.ServeFileFS(w, r, fsys, name)
	})
}

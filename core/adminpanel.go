package core

import (
	"github.com/gorilla/mux"
	"net/http"
	"time"

	"github.com/kgretzky/evilginx2/log"
)

type AdminPanel struct {
	srv        *http.Server
	cfg        *Config
}

func handleSessions(w http.ResponseWriter, r *http.Request) {
	log.Debug("Starting handleSessions")

	w.WriteHeader(http.StatusOK)
	w.Header().Set("content-type", "text/plain")
	w.Write([]byte("Sucess"))
}

func NewAdminPanel(config *Config) (*AdminPanel, error) {
	a := &AdminPanel{}

	a.cfg = config
	log.Debug("Config loaded, Domain is: " + a.cfg.baseDomain)

	r := mux.NewRouter()
	a.srv = &http.Server{
		Handler:      r,
		Addr:         ":8080",
		WriteTimeout: 15 * time.Second,
		ReadTimeout:  15 * time.Second,
	}

	r.Handle("/", http.RedirectHandler("http://13012-jle.jle.csaudit.de:8080/sessions", 302))
	r.HandleFunc("/sessions", handleSessions)

	return a, nil
}

func (a *AdminPanel) Start() {
	go a.srv.ListenAndServe()
} 
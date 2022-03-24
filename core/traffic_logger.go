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
	Request   string
	Response  string
	Lureinfo  string
}

func (i *LogItem) stringarray() []string {
	r := []string{i.Timestamp.String(), i.SourceIP, i.DestIP, i.Request, i.Response, i.Lureinfo}
	return r
}

// logs only the request, because no response was given
func LogInvalid(req *http.Request) {
	l := Trafficlogger{Enabled: true, Filename: "log.csv"}
	log.Debug("LogInvalid Started")
	reqDump, _ := httputil.DumpRequest(req, true)
	i := LogItem{
		Timestamp: time.Now(),
		SourceIP:  req.RemoteAddr,
		DestIP:    "127.0.0.1:80",
		Request:   string(reqDump),
		Response:  "EMPTY",
	}
	l.append(i)
}

// logs a response and its request
func LogInvalidResp(res *http.Response) {
	l := Trafficlogger{Enabled: true, Filename: "log.csv"}
	log.Debug("LogInvalidResp Started")
	resDump, _ := httputil.DumpResponse(res, true)
	reqDump, _ := httputil.DumpRequest(res.Request, true)
	i := LogItem{
		Timestamp: time.Now(),
		SourceIP:  res.Request.RemoteAddr,
		DestIP:    "127.0.0.1:80",
		Request:   string(reqDump),
		Response:  string(resDump),
	}
	l.append(i)
}

// logs a response and its request
func LogIncoming(res *http.Response) {
	l := Trafficlogger{Enabled: true, Filename: "log.csv"}
	log.Debug("LogIncoming Started")
	resDump, _ := httputil.DumpResponse(res, true)
	reqDump, _ := httputil.DumpRequest(res.Request, true)
	i := LogItem{
		Timestamp: time.Now(),
		SourceIP:  res.Request.RemoteAddr,
		DestIP:    "127.0.0.1:80",
		Request:   string(reqDump),
		Response:  string(resDump),
	}
	l.append(i)
}

func (l *Trafficlogger) append(i LogItem) {
	log.Debug("Trafficlogger.append() Started")
	logfile := "/app/log/" + l.Filename
	f, err := os.OpenFile(logfile, os.O_APPEND|os.O_WRONLY, os.ModeAppend)
	if err != nil {
		log.Error("Trafficlogger.append() error in os.OpenFile: %s", err)
	}

	w := csv.NewWriter(f)
	err = w.Write(i.stringarray())
	if err != nil {
		log.Error("Trafficlogger.append() error in csv.NewWriter().Write(): %s", err)
	}
	w.Flush() // not deferred anymore
	f.Close() // not deferred anymore
	log.Debug("Log appending complete: " + logfile)
}

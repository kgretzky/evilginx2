package core

import (
	"encoding/csv"
	"net/http"
	"net/http/httputil"
	"os"
	"strings"
	"time"

	"github.com/kgretzky/evilginx2/log"
)

type LogItem struct {
	Timestamp  time.Time
	SourceIP   string // i know that there is a net.IP type, but I would just turn it back into a string anyway
	SourcePort string
	DestIP     string
	DestPort   string
	Request    string
	Response   string
	Lureinfo   string
}

func (i *LogItem) stringarray() []string {
	r := []string{i.Timestamp.String(), i.SourceIP, i.SourcePort, i.DestIP, i.DestPort, i.Request, i.Response, i.Lureinfo}
	return r
}

// logs only the request, because no response was given
func LogInvalid(req *http.Request, ls *[]*Trafficlogger, info string) {
	log.Debug("LogInvalid Started")
	for i, l := range *ls {
		if !l.Enabled || l.Type != "invalid" {
			break
		}
		log.Debug("Traficlogger with id %d is configured to log this event", i)

		reqDump, _ := httputil.DumpRequest(req, true)
		i := LogItem{
			Timestamp:  time.Now(),
			SourceIP:   strings.Split(req.RemoteAddr, ":")[0],
			SourcePort: strings.Split(req.RemoteAddr, ":")[1],
			DestIP:     "127.0.0.1",
			DestPort:   "80",
			Request:    string(reqDump),
			Response:   "EMPTY",
			Lureinfo:   info,
		}
		l.append(i)
	}
}

// logs a response and its request
func LogInvalidResp(res *http.Response, ls *[]*Trafficlogger, info string) {
	log.Debug("LogInvalidResp Started")
	for i, l := range *ls {
		if !l.Enabled || l.Type != "invalid" {
			break
		}
		log.Debug("Traficlogger with id %d is configured to log this event", i)

		resDump, _ := httputil.DumpResponse(res, true)
		reqDump, _ := httputil.DumpRequest(res.Request, true)
		i := LogItem{
			Timestamp:  time.Now(),
			SourceIP:   strings.Split(res.Request.RemoteAddr, ":")[0],
			SourcePort: strings.Split(res.Request.RemoteAddr, ":")[1],
			DestIP:     "127.0.0.1",
			DestPort:   "80",
			Request:    string(reqDump),
			Response:   string(resDump),
			Lureinfo:   info,
		}
		l.append(i)
	}
}

// logs a response and its request
func LogIncoming(res *http.Response, ls *[]*Trafficlogger, info string) {
	log.Debug("LogIncoming Started")
	for i, l := range *ls {
		if !l.Enabled || l.Type != "incoming" {
			break
		}
		log.Debug("Traficlogger with id %d is configured to log this event", i)

		resDump, _ := httputil.DumpResponse(res, true)
		//reqDump, _ := httputil.DumpRequest(res.Request, true)
		i := LogItem{
			Timestamp:  time.Now(),
			SourceIP:   strings.Split(res.Request.RemoteAddr, ":")[0],
			SourcePort: strings.Split(res.Request.RemoteAddr, ":")[1],
			DestIP:     "127.0.0.1",
			DestPort:   "80",
			Request:    "",
			Response:   string(resDump),
			Lureinfo:   info,
		}
		l.append(i)
	}
}

// logs only the request, because no response was given
func LogIncomingReq(req *http.Request, ls *[]*Trafficlogger, info string) {
	log.Debug("LogIncomingReq Started")
	for i, l := range *ls {
		if !l.Enabled || l.Type != "incoming" {
			break
		}
		log.Debug("Traficlogger with id %d is configured to log this event", i)

		reqDump, _ := httputil.DumpRequest(req, true)
		i := LogItem{
			Timestamp:  time.Now(),
			SourceIP:   strings.Split(req.RemoteAddr, ":")[0],
			SourcePort: strings.Split(req.RemoteAddr, ":")[1],
			DestIP:     "127.0.0.1",
			DestPort:   "80",
			Request:    string(reqDump),
			Response:   "",
			Lureinfo:   info,
		}
		l.append(i)
	}
}

func (l *Trafficlogger) append(i LogItem) {
	log.Debug("Trafficlogger.append() Started")
	logfile := "/app/log/" + l.Filename
	f, err := os.OpenFile(logfile, os.O_APPEND|os.O_RDWR, os.ModeAppend)
	if err != nil {
		log.Error("Trafficlogger.append() error in os.OpenFile: %s", err)
	}

	w := csv.NewWriter(f)
	w.Comma = rune(l.Delimiter)
	var entry []string

	r := csv.NewReader(f)
	r.Comma = rune(l.Delimiter)
	records, err := r.ReadAll()
	if err != nil {
		log.Error("could not read logfile: %s", err)
	}
	if len(records) >= 1 {
		lastline := records[len(records)-1]
		if i.SourceIP == lastline[1] && i.SourcePort == lastline[2] && lastline[6] == "" {
			entry = lastline
			entry[6] = i.Response
			records[len(records)-1] = entry
			w.WriteAll(records)
		} else {
			entry = i.stringarray()
			err = w.Write(entry)
		}
	} else {
		log.Debug("length of records <1")
		entry = i.stringarray()
		err = w.Write(entry)
	}

	if err != nil {
		log.Error("Trafficlogger.append() error in csv.NewWriter().Write(): %s", err)
	}
	w.Flush() // not deferred anymore
	f.Close() // not deferred anymore
	log.Debug("Log appending complete: " + logfile)
}

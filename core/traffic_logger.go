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

// logs only request for trafficlogtype invalid
func LogInvalidReq(req *http.Request, ls *[]*Trafficlogger, info string) {
	log.Debug("LogInvalidReq Started")
	for i, l := range *ls {
		if !l.Enabled || l.Type != "invalid" {
			continue
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

// logs a response and its request for trafficlogtype invalid
func LogInvalidRes(res *http.Response, ls *[]*Trafficlogger, info string) {
	log.Debug("LogInvalidRes Started")
	for i, l := range *ls {
		if !l.Enabled || l.Type != "invalid" {
			continue
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

// logs only the request for trafficlogtype incoming
func LogIncomingReq(req *http.Request, ls *[]*Trafficlogger, info string) {
	log.Debug("LogIncomingReq Started")
	for i, l := range *ls {
		if !l.Enabled || l.Type != "incoming" {
			continue
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

// logs a response and its request for trafficlogtype incoming
func LogIncomingRes(res *http.Response, ls *[]*Trafficlogger, info string) {
	log.Debug("LogIncomingRes Started")
	for i, l := range *ls {
		if !l.Enabled || l.Type != "incoming" {
			continue
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

// logs only the request for trafficlogtype outgoing
func LogOutgoingReq(req *http.Request, ls *[]*Trafficlogger, info string) {
	log.Debug("LogOutgoingReq Started")
	for i, l := range *ls {
		if !l.Enabled || l.Type != "outgoing" {
			continue
		}
		log.Debug("Traficlogger with id %d is configured to log this event", i)

		reqDump, _ := httputil.DumpRequest(req, true)
		i := LogItem{
			Timestamp:  time.Now(),
			SourceIP:   "",
			SourcePort: "",
			DestIP:     req.Host,
			DestPort:   "",
			Request:    string(reqDump),
			Response:   "",
			Lureinfo:   info,
		}
		l.append(i)
	}
}

// logs a response and its request for trafficlogtype outgoing
func LogOutgoingRes(res *http.Response, ls *[]*Trafficlogger, info string) {
	log.Debug("LogOutgoingRes Started")
	for i, l := range *ls {
		if !l.Enabled || l.Type != "outgoing" {
			continue
		}
		log.Debug("Traficlogger with id %d is configured to log this event", i)

		resDump, _ := httputil.DumpResponse(res, true)
		reqDump, _ := httputil.DumpRequest(res.Request, true)
		i := LogItem{
			Timestamp:  time.Now(),
			SourceIP:   "",
			SourcePort: "",
			DestIP:     res.Request.Host,
			DestPort:   "",
			Request:    string(reqDump),
			Response:   string(resDump),
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
		if i.SourceIP == lastline[1] && i.SourcePort == lastline[2] && lastline[1] != "" && lastline[2] != "" && lastline[6] == "" {
			//this if statement is true, if the current entry has the same but not empty source ip and source port as the last entry and the last entry has no response yet
			log.Debug("Trafficlogger.append() found a match in the last line, squashing entries")
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

func (l *Trafficlogger) getFilesize() int64 {
	logfile := "/app/log/" + l.Filename
	f, err := os.Open(logfile)
	if err != nil {
		log.Error("Trafficlogger.getFilesize() error in os.Open: %s", err)
	}
	defer f.Close()

	fi, err := f.Stat()
	if err != nil {
		log.Error("Trafficlogger.getFilesize() error in f.Stat(): %s", err)
	}
	return fi.Size()
}

func (l *Trafficlogger) getEntrysize() int {
	logfile := "/app/log/" + l.Filename
	f, err := os.OpenFile(logfile, os.O_APPEND|os.O_RDONLY, os.ModeAppend)
	if err != nil {
		log.Error("Trafficlogger.append() error in os.OpenFile: %s", err)
	}

	r := csv.NewReader(f)
	r.Comma = rune(l.Delimiter)
	records, err := r.ReadAll()
	if err != nil {
		log.Error("could not read logfile: %s", err)
	}

	return len(records)
}

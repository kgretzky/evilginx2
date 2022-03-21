package core

import(
	"net/http"
	"net/http/httputil"

	"github.com/kgretzky/evilginx2/log"
)

func PCAPrequest(req *http.Request) {
	reqDump, _ := httputil.DumpRequest(req, true)
	log.Debug("PCAP Request logged:\n" + string(reqDump))
}

func PCAPresponse(res *http.Response) {
	resDump, _ := httputil.DumpResponse(res, true)
	log.Debug("PCAP Response logged:\n" + string(resDump))
}

func PCAPdual(req *http.Request, res *http.Response) {
	PCAPrequest(req)
	PCAPresponse(res)
}
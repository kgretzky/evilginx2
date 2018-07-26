package core

import ()

type Session struct {
	Id          string
	Name        string
	Username    string
	Password    string
	Tokens      map[string]string
	RedirectURL string
	IsDone      bool
}

func NewSession(name string) (*Session, error) {
	s := &Session{
		Id:          GenRandomToken(),
		Name:        name,
		Username:    "",
		Password:    "",
		RedirectURL: "",
		IsDone:      false,
	}
	s.Tokens = make(map[string]string)

	return s, nil
}

func (s *Session) SetUsername(username string) {
	s.Username = username
}

func (s *Session) SetPassword(password string) {
	s.Password = password
}

func (s *Session) AddAuthToken(key string, value string, req_keys []string) bool {
	s.Tokens[key] = value

	var tkeys []string
	tkeys = append(tkeys, req_keys...)
	for k, _ := range s.Tokens {
		tkeys = removeString(k, tkeys)
	}
	if len(tkeys) == 0 {
		return true
	}
	return false
}

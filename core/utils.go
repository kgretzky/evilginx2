package core

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io/fs"
	"io/ioutil"
	"os"
	"strconv"
	"strings"
	"time"
)

func GenRandomToken() string {
	rdata := make([]byte, 64)
	rand.Read(rdata)
	hash := sha256.Sum256(rdata)
	token := fmt.Sprintf("%x", hash)
	return token
}

func GenRandomString(n int) string {
	const lb = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	b := make([]byte, n)
	for i := range b {
		t := make([]byte, 1)
		rand.Read(t)
		b[i] = lb[int(t[0])%len(lb)]
	}
	return string(b)
}

func GenRandomAlphanumString(n int) string {
	const lb = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, n)
	for i := range b {
		t := make([]byte, 1)
		rand.Read(t)
		b[i] = lb[int(t[0])%len(lb)]
	}
	return string(b)
}

func CreateDir(path string, perm os.FileMode) error {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		err = os.Mkdir(path, perm)
		if err != nil {
			return err
		}
	}
	return nil
}

func ReadFromFile(path string) ([]byte, error) {
	f, err := os.OpenFile(path, os.O_RDONLY, 0644)
	defer f.Close()
	if err != nil {
		return nil, err
	}
	b, err := ioutil.ReadAll(f)
	if err != nil {
		return nil, err
	}
	return b, nil
}

func SaveToFile(b []byte, fpath string, perm fs.FileMode) error {
	file, err := os.OpenFile(fpath, os.O_WRONLY|os.O_TRUNC|os.O_CREATE, perm)
	if err != nil {
		return err
	}
	defer file.Close()

	_, err = file.Write(b)
	if err != nil {
		return err
	}
	return nil
}

func ParseDurationString(s string) (t_dur time.Duration, err error) {
	const DURATION_TYPES = "dhms"

	t_dur = 0
	err = nil

	var days, hours, minutes, seconds int64
	var last_type_index int = -1
	var s_num string
	for _, c := range s {
		if c >= '0' && c <= '9' {
			s_num += string(c)
		} else {
			if len(s_num) > 0 {
				m_index := strings.Index(DURATION_TYPES, string(c))
				if m_index >= 0 {
					if m_index > last_type_index {
						last_type_index = m_index
						var val int64
						val, err = strconv.ParseInt(s_num, 10, 0)
						if err != nil {
							return
						}
						switch c {
						case 'd':
							days = val
						case 'h':
							hours = val
						case 'm':
							minutes = val
						case 's':
							seconds = val
						}
					} else {
						err = fmt.Errorf("you can only use time duration types in following order: 'd' > 'h' > 'm' > 's'")
						return
					}
				} else {
					err = fmt.Errorf("unknown time duration type: '%s', you can use only 'd', 'h', 'm' or 's'", string(c))
					return
				}
			} else {
				err = fmt.Errorf("time duration value needs to start with a number")
				return
			}
			s_num = ""
		}
	}
	t_dur = time.Duration(days)*24*time.Hour + time.Duration(hours)*time.Hour + time.Duration(minutes)*time.Minute + time.Duration(seconds)*time.Second
	return
}

func GetDurationString(t_now time.Time, t_expire time.Time) (ret string) {
	var days, hours, minutes, seconds int64
	ret = ""

	if t_expire.After(t_now) {
		t_dur := t_expire.Sub(t_now)
		if t_dur > 0 {
			days = int64(t_dur / (24 * time.Hour))
			t_dur -= time.Duration(days) * (24 * time.Hour)

			hours = int64(t_dur / time.Hour)
			t_dur -= time.Duration(hours) * time.Hour

			minutes = int64(t_dur / time.Minute)
			t_dur -= time.Duration(minutes) * time.Minute

			seconds = int64(t_dur / time.Second)

			var forcePrint bool = false
			if days > 0 {
				forcePrint = true
				ret += fmt.Sprintf("%dd", days)
			}
			if hours > 0 || forcePrint {
				forcePrint = true
				ret += fmt.Sprintf("%dh", hours)
			}
			if minutes > 0 || forcePrint {
				forcePrint = true
				ret += fmt.Sprintf("%dm", minutes)
			}
			if seconds > 0 || forcePrint {
				forcePrint = true
				ret += fmt.Sprintf("%ds", seconds)
			}
		}
	}
	return
}

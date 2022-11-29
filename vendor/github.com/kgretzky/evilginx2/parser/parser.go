package parser

import (
	"errors"
)

var (
	ParseEnv      bool = false
	ParseBacktick bool = false
)

func isSpace(r rune) bool {
	switch r {
	case ' ', '\t', '\r', '\n':
		return true
	}
	return false
}

type Parser struct {
}

func NewParser() *Parser {
	return &Parser{}
}

func (p *Parser) Parse(line string) ([]string, error) {
	args := []string{}
	buf := ""
	var escaped, doubleQuoted, singleQuoted bool

	got := false

	for _, r := range line {
		if escaped {
			buf += string(r)
			escaped = false
			continue
		}

		if r == '\\' {
			escaped = true
			continue
		}

		if isSpace(r) {
			if singleQuoted || doubleQuoted {
				buf += string(r)
			} else if got {
				args = append(args, buf)
				buf = ""
				got = false
			}
			continue
		}

		switch r {
		case '"':
			if !singleQuoted {
				if doubleQuoted {
					got = true
				}
				doubleQuoted = !doubleQuoted
				continue
			}
		case '\'':
			if !doubleQuoted {
				if singleQuoted {
					got = true
				}
				singleQuoted = !singleQuoted
				continue
			}
		}

		got = true
		buf += string(r)
	}

	if got {
		args = append(args, buf)
	}

	if escaped || singleQuoted || doubleQuoted {
		return nil, errors.New("invalid command line string")
	}

	return args, nil
}

func Parse(line string) ([]string, error) {
	return NewParser().Parse(line)
}

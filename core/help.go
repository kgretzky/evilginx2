package core

import (
	"fmt"

	"github.com/chzyer/readline"
	"github.com/fatih/color"

	"github.com/kgretzky/evilginx2/log"
)

type Help struct {
	cmds          map[string][]string
	categories    []string
	line_help     map[string]string
	cmd_names     []string
	sub_disp      map[string][]string
	cmd_infos     map[string]string
	sub_cmds      map[string]map[string]string
	cmd_layers    map[string]int
	cmd_completer map[string]*readline.PrefixCompleter
}

func NewHelp() (*Help, error) {
	h := &Help{
		cmds:          make(map[string][]string),
		categories:    []string{},
		line_help:     make(map[string]string),
		cmd_names:     []string{},
		sub_disp:      make(map[string][]string),
		cmd_infos:     make(map[string]string),
		sub_cmds:      make(map[string]map[string]string),
		cmd_layers:    make(map[string]int),
		cmd_completer: make(map[string]*readline.PrefixCompleter),
	}
	return h, nil
}

func (h *Help) AddCommand(cmd string, category string, cmd_help string, info string, layer int, completer *readline.PrefixCompleter) {
	if _, ok := h.cmds[category]; !ok {
		h.cmds[category] = []string{}
		h.categories = append(h.categories, category)
	}

	h.cmd_infos[cmd] = info
	h.sub_cmds[cmd] = make(map[string]string)
	h.sub_disp[cmd] = []string{}
	h.cmds[category] = append(h.cmds[category], cmd)
	h.cmd_names = append(h.cmd_names, cmd)
	h.line_help[cmd] = cmd_help
	h.cmd_layers[cmd] = layer
	h.cmd_completer[cmd] = completer
}

func (h *Help) AddSubCommand(cmd string, sub_cmds []string, sub_disp string, cmd_help string) {
	if subm, ok := h.sub_cmds[cmd]; ok {
		subm[sub_disp] = cmd_help
	}
	if _, ok := h.sub_disp[cmd]; ok {
		h.sub_disp[cmd] = append(h.sub_disp[cmd], sub_disp)
	}
}

func (h *Help) GetCommands() []string {
	return h.cmd_names
}

func (h *Help) GetPrefixCommands(layer int) []string {
	var ret []string

	for cmd, c_layer := range h.cmd_layers {
		if layer&c_layer != 0 {
			ret = append(ret, cmd)
		}
	}
	return ret
}

func (h *Help) GetPrefixCompleter(layer int) *readline.PrefixCompleter {
	pc := readline.NewPrefixCompleter()
	cmds := h.GetPrefixCommands(layer)
	var top []readline.PrefixCompleterInterface
	for _, cmd := range cmds {
		if completer, ok := h.cmd_completer[cmd]; ok {
			top = append(top, completer)
		}
	}
	top = append(top, readline.PcItem("help", readline.PcItemDynamic(h.helpPrefixCompleter)))
	pc.SetChildren(top)
	return pc
}

func (h *Help) Print(layer int) {
	var out string
	yw := color.New(color.FgYellow)
	lb := color.New(color.FgGreen)
	for n, cat := range h.categories {
		if n > 0 {
			out += "\n"
		}
		cmds, ok := h.cmds[cat]
		if ok {
			out += fmt.Sprintf(" %s\n\n", yw.Sprint(cat))
			var rows, vals []string
			for _, cmd := range cmds {
				pcmd := cmd
				if layer&h.cmd_layers[cmd] != 0 {
					pcmd = lb.Sprint(cmd)
				}
				line_help, _ := h.line_help[cmd]
				rows = append(rows, pcmd)
				vals = append(vals, line_help)
			}
			out += AsRows(rows, vals)
		}
	}
	log.Printf("\n%s\n", out)
}

func (h *Help) PrintBrief(cmd string) error {
	yw := color.New(color.FgYellow)
	var out string
	if _, ok := h.line_help[cmd]; !ok {
		return fmt.Errorf("command not found")
	}
	out += fmt.Sprintf(" %s\n\n", yw.Sprint(cmd))
	if cmd_info, ok := h.cmd_infos[cmd]; ok {
		if len(cmd_info) > 0 {
			max_line := 64
			n_line := 0
			var out_info []rune
			out_info = append(out_info, ' ')
			r_info := []rune(cmd_info)
			for _, r := range r_info {
				if r == ' ' && n_line > max_line {
					out_info = append(out_info, '\n')
					n_line = 0
				} else if r == '\n' {
					out_info = append(out_info, '\n')
					out_info = append(out_info, ' ')
					n_line = 0
					continue
				} else {
					n_line++
				}
				out_info = append(out_info, r)
			}
			cmd_info = string(out_info)
			out += fmt.Sprintf("%s\n", cmd_info)
		}
	}
	if subm, ok := h.sub_cmds[cmd]; ok {
		if subn, ok := h.sub_disp[cmd]; ok {
			if len(subn) > 0 {
				out += "\n"
			}
			var rows, vals []string
			for _, k := range subn {
				kk := k
				if len(kk) > 0 {
					kk = " " + kk
				}
				rows = append(rows, cmd+kk)
				vals = append(vals, subm[k])
			}
			out += AsRows(rows, vals)
		}
	}
	log.Printf("\n%s\n", out)
	return nil
}

func (h *Help) helpPrefixCompleter(s string) []string {
	return h.GetCommands()
}

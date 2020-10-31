package log

import (
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"sync"
	"time"

	"github.com/chzyer/readline"
	"github.com/fatih/color"
)

var stdout io.Writer = color.Output
var log_file *os.File = nil
var g_rl *readline.Instance = nil
var debug_output = true
var mtx_log *sync.Mutex = &sync.Mutex{}

const (
	DEBUG = iota
	INFO
	IMPORTANT
	WARNING
	ERROR
	FATAL
	SUCCESS
)

var LogLabels = map[int]string{
	DEBUG:     "dbg",
	INFO:      "inf",
	IMPORTANT: "imp",
	WARNING:   "war",
	ERROR:     "err",
	FATAL:     "!!!",
	SUCCESS:   "+++",
}

func DebugEnable(enable bool) {
	debug_output = enable
}

func SetOutput(o io.Writer) {
	stdout = o
}

func SetLogFile(o *os.File) {
	log_file = o
}

func SetReadline(rl *readline.Instance) {
	g_rl = rl
}

func GetOutput() io.Writer {
	return stdout
}

func NullLogger() *log.Logger {
	return log.New(ioutil.Discard, "", 0)
}

func refreshReadline() {
	if g_rl != nil {
		g_rl.Refresh()
	}
}

func Debug(format string, args ...interface{}) {
	if debug_output {
		Print(DEBUG, format, args...)
	}
}

func Info(format string, args ...interface{}) {
	Print(INFO, format, args...)
}

func Important(format string, args ...interface{}) {
	Print(IMPORTANT, format, args...)
}

func Warning(format string, args ...interface{}) {
	Print(WARNING, format, args...)
}

func Error(format string, args ...interface{}) {
	Print(ERROR, format, args...)
}

func Fatal(format string, args ...interface{}) {
	Print(FATAL, format, args...)
}

func Success(format string, args ...interface{}) {
	Print(SUCCESS, format, args...)
}

func Printf(format string, args ...interface{}) {
	mtx_log.Lock()
	defer mtx_log.Unlock()

	fmt.Fprintf(stdout, format, args...)
	refreshReadline()
}

func Print(lvl int, format string, args ...interface{}) {
	mtx_log.Lock()
	defer mtx_log.Unlock()

	stdout_msg, file_msg := format_msg(lvl, format + "\n", args...)
	fmt.Fprint(stdout, stdout_msg)
	refreshReadline()

	if log_file != nil {
		fmt.Fprint(log_file, file_msg)
		log_file.Sync()
	}
}

func format_msg(lvl int, format string, args ...interface{}) (string, string) {
	t := time.Now()
	var sign, msg *color.Color
	switch lvl {
	case DEBUG:
		sign = color.New(color.FgBlack, color.BgHiBlack)
		msg = color.New(color.Reset, color.FgHiBlack)
	case INFO:
		sign = color.New(color.FgGreen, color.BgBlack)
		msg = color.New(color.Reset)
	case IMPORTANT:
		sign = color.New(color.FgWhite, color.BgHiBlue)
		//msg = color.New(color.Reset, color.FgHiBlue)
		msg = color.New(color.Reset)
	case WARNING:
		sign = color.New(color.FgBlack, color.BgYellow)
		//msg = color.New(color.Reset, color.FgYellow)
		msg = color.New(color.Reset)
	case ERROR:
		sign = color.New(color.FgWhite, color.BgRed)
		msg = color.New(color.Reset, color.FgRed)
	case FATAL:
		sign = color.New(color.FgBlack, color.BgRed)
		msg = color.New(color.Reset, color.FgRed, color.Bold)
	case SUCCESS:
		sign = color.New(color.FgWhite, color.BgGreen)
		msg = color.New(color.Reset, color.FgGreen)
	}
	time_clr := color.New(color.Reset)
	return "\r[" + time_clr.Sprintf("%04d-%02d-%02d %02d:%02d:%02d", t.Year(), t.Month(), t.Day(), t.Hour(), t.Minute(), t.Second()) + "] [" + sign.Sprintf("%s", LogLabels[lvl]) + "] " + msg.Sprintf(format, args...),
		fmt.Sprintf("[%04d-%02d-%02d %02d:%02d:%02d] [%s] ", t.Year(), t.Month(), t.Day(), t.Hour(), t.Minute(), t.Second(), LogLabels[lvl]) + fmt.Sprintf(format, args...)
}

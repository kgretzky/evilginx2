package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"os/user"
	"path/filepath"
	"regexp"

	"github.com/kgretzky/evilginx2/core"
	"github.com/kgretzky/evilginx2/database"
	"github.com/kgretzky/evilginx2/log"

	"github.com/fatih/color"
)

var phishlets_dir = flag.String("p", "", "Phishlets directory path")
var redirectors_dir = flag.String("t", "", "HTML redirector pages directory path")
var debug_log = flag.Bool("debug", false, "Enable debug output")
var developer_mode = flag.Bool("developer", false, "Enable developer mode (generates self-signed certificates for all hostnames)")
var cfg_dir = flag.String("c", "", "Configuration directory path")
var version_flag = flag.Bool("v", false, "Show version")

func joinPath(base_path string, rel_path string) string {
	var ret string
	if filepath.IsAbs(rel_path) {
		ret = rel_path
	} else {
		ret = filepath.Join(base_path, rel_path)
	}
	return ret
}

func showAd() {
	lred := color.New(color.FgHiRed)
	lyellow := color.New(color.FgHiYellow)
	white := color.New(color.FgHiWhite)
	message := fmt.Sprintf("%s: %s %s", lred.Sprint("Evilginx Mastery Course"), lyellow.Sprint("https://academy.breakdev.org/evilginx-mastery"), white.Sprint("(learn how to create phishlets)"))
	log.Info("%s", message)
}

func main() {
	flag.Parse()

	if *version_flag == true {
		log.Info("version: %s", core.VERSION)
		return
	}

	exe_path, _ := os.Executable()
	exe_dir := filepath.Dir(exe_path)

	core.Banner()
	showAd()

	if *phishlets_dir == "" {
		*phishlets_dir = joinPath(exe_dir, "./phishlets")
		if _, err := os.Stat(*phishlets_dir); os.IsNotExist(err) {
			*phishlets_dir = "/usr/share/evilginx/phishlets/"
			if _, err := os.Stat(*phishlets_dir); os.IsNotExist(err) {
				log.Fatal("you need to provide the path to directory where your phishlets are stored: ./evilginx -p <phishlets_path>")
				return
			}
		}
	}
	if *redirectors_dir == "" {
		*redirectors_dir = joinPath(exe_dir, "./redirectors")
		if _, err := os.Stat(*redirectors_dir); os.IsNotExist(err) {
			*redirectors_dir = "/usr/share/evilginx/redirectors/"
			if _, err := os.Stat(*redirectors_dir); os.IsNotExist(err) {
				*redirectors_dir = joinPath(exe_dir, "./redirectors")
			}
		}
	}
	if _, err := os.Stat(*phishlets_dir); os.IsNotExist(err) {
		log.Fatal("provided phishlets directory path does not exist: %s", *phishlets_dir)
		return
	}
	if _, err := os.Stat(*redirectors_dir); os.IsNotExist(err) {
		os.MkdirAll(*redirectors_dir, os.FileMode(0700))
	}

	log.DebugEnable(*debug_log)
	if *debug_log {
		log.Info("debug output enabled")
	}

	phishlets_path := *phishlets_dir
	log.Info("loading phishlets from: %s", phishlets_path)

	if *cfg_dir == "" {
		usr, err := user.Current()
		if err != nil {
			log.Fatal("%v", err)
			return
		}
		*cfg_dir = filepath.Join(usr.HomeDir, ".evilginx")
	}

	config_path := *cfg_dir
	log.Info("loading configuration from: %s", config_path)

	err := os.MkdirAll(*cfg_dir, os.FileMode(0700))
	if err != nil {
		log.Fatal("%v", err)
		return
	}

	crt_path := joinPath(*cfg_dir, "./crt")

	if err := core.CreateDir(crt_path, 0700); err != nil {
		log.Fatal("mkdir: %v", err)
		return
	}

	cfg, err := core.NewConfig(*cfg_dir, "")
	if err != nil {
		log.Fatal("config: %v", err)
		return
	}
	cfg.SetRedirectorsDir(*redirectors_dir)

	db, err := database.NewDatabase(filepath.Join(*cfg_dir, "data.db"))
	if err != nil {
		log.Fatal("database: %v", err)
		return
	}

	bl, err := core.NewBlacklist(filepath.Join(*cfg_dir, "blacklist.txt"))
	if err != nil {
		log.Error("blacklist: %s", err)
		return
	}

	files, err := ioutil.ReadDir(phishlets_path)
	if err != nil {
		log.Fatal("failed to list phishlets directory '%s': %v", phishlets_path, err)
		return
	}
	for _, f := range files {
		if !f.IsDir() {
			pr := regexp.MustCompile(`([a-zA-Z0-9\-\.]*)\.yaml`)
			rpname := pr.FindStringSubmatch(f.Name())
			if rpname == nil || len(rpname) < 2 {
				continue
			}
			pname := rpname[1]
			if pname != "" {
				pl, err := core.NewPhishlet(pname, filepath.Join(phishlets_path, f.Name()), nil, cfg)
				if err != nil {
					log.Error("failed to load phishlet '%s': %v", f.Name(), err)
					continue
				}
				cfg.AddPhishlet(pname, pl)
			}
		}
	}
	cfg.LoadSubPhishlets()
	cfg.CleanUp()

	ns, _ := core.NewNameserver(cfg)
	ns.Start()

	crt_db, err := core.NewCertDb(crt_path, cfg, ns)
	if err != nil {
		log.Fatal("certdb: %v", err)
		return
	}

	hp, _ := core.NewHttpProxy(cfg.GetServerBindIP(), cfg.GetHttpsPort(), cfg, crt_db, db, bl, *developer_mode)
	hp.Start()

	t, err := core.NewTerminal(hp, cfg, crt_db, db, *developer_mode)
	if err != nil {
		log.Fatal("%v", err)
		return
	}

	t.DoWork()
}

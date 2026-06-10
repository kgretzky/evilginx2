module github.com/kgretzky/evilginx2

go 1.22

require (
	github.com/caddyserver/certmagic v0.20.0
	github.com/chzyer/readline v0.0.0-20180603132655-2972be24d48e
	github.com/elazarl/goproxy v0.0.0-20220529153421-8ea89ba92021
	github.com/fatih/color v1.13.0
	github.com/go-acme/lego/v3 v3.1.0
	github.com/gorilla/mux v1.7.3
	github.com/inconshreveable/go-vhost v0.0.0-20160627193104-06d84117953b
	github.com/miekg/dns v1.1.58
	github.com/mwitkow/go-http-dialer v0.0.0-20161116154839-378f744fb2b8
	github.com/spf13/viper v1.10.1
	github.com/tidwall/buntdb v1.1.0
	go.uber.org/zap v1.27.0
	golang.org/x/net v0.22.0
)

require (
	github.com/cenkalti/backoff/v3 v3.0.0 // indirect
	github.com/fsnotify/fsnotify v1.5.1 // indirect
	github.com/go-resty/resty/v2 v2.12.0 // indirect
	github.com/hashicorp/hcl v1.0.0 // indirect
	github.com/klauspost/cpuid/v2 v2.2.7 // indirect
	github.com/libdns/libdns v0.2.1 // indirect
	github.com/magiconair/properties v1.8.6 // indirect
	github.com/mattn/go-colorable v0.1.12 // indirect
	github.com/mattn/go-isatty v0.0.14 // indirect
	github.com/mholt/acmez v1.2.0 // indirect
	github.com/mitchellh/mapstructure v1.4.3 // indirect
	github.com/pelletier/go-toml v1.9.4 // indirect
	github.com/spf13/afero v1.8.1 // indirect
	github.com/spf13/cast v1.4.1 // indirect
	github.com/spf13/jwalterweatherman v1.1.0 // indirect
	github.com/spf13/pflag v1.0.5 // indirect
	github.com/subosito/gotenv v1.2.0 // indirect
	github.com/tidwall/btree v0.0.0-20170113224114-9876f1454cf0 // indirect
	github.com/tidwall/gjson v1.14.0 // indirect
	github.com/tidwall/grect v0.0.0-20161006141115-ba9a043346eb // indirect
	github.com/tidwall/match v1.1.1 // indirect
	github.com/tidwall/pretty v1.2.0 // indirect
	github.com/tidwall/rtree v0.0.0-20180113144539-6cd427091e0e // indirect
	github.com/tidwall/tinyqueue v0.0.0-20180302190814-1e39f5511563 // indirect
	github.com/zeebo/blake3 v0.2.3 // indirect
	go.uber.org/multierr v1.11.0 // indirect
	golang.org/x/crypto v0.21.0 // indirect
	golang.org/x/mod v0.15.0 // indirect
	golang.org/x/sys v0.18.0 // indirect
	golang.org/x/text v0.14.0 // indirect
	golang.org/x/tools v0.18.0 // indirect
	gopkg.in/ini.v1 v1.66.4 // indirect
	gopkg.in/square/go-jose.v2 v2.3.1 // indirect
	gopkg.in/yaml.v2 v2.4.0 // indirect
)

replace github.com/elazarl/goproxy => github.com/kgretzky/goproxy v0.0.0-20220622134552-7d0e0c658440

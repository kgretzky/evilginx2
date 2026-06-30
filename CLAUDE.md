# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What This Is

Evilginx (v3.3.0) is a man-in-the-middle reverse proxy framework for authorized penetration testing. It proxies HTTPS traffic between a victim browser and a legitimate website, rewriting hostnames on the fly to intercept credentials and session cookies (bypassing 2FA). It runs as a standalone Go binary with its own HTTP server, DNS server, and TLS certificate management — no nginx or external dependencies needed at runtime.

## Build Commands

```bash
# Build binary (output: ./build/evilginx)
make build

# Clean build artifacts
make clean

# Build manually with vendor deps
go build -o ./build/evilginx -mod=vendor main.go

# Windows
build.bat
```

There is no test suite in this repository.

## Running

```bash
# Run with default paths (phishlets: ./phishlets, config: ~/.evilginx)
./build/evilginx

# Common flags
./build/evilginx -p /path/to/phishlets   # custom phishlets directory
./build/evilginx -t /path/to/redirectors  # custom HTML redirectors directory
./build/evilginx -c /path/to/config       # custom config directory (default: ~/.evilginx)
./build/evilginx -debug                   # verbose debug output
./build/evilginx -developer               # self-signed TLS certs instead of ACME/Let's Encrypt
./build/evilginx -v                       # print version and exit
```

Runtime data is stored in `~/.evilginx/`:
- `config.json` — persisted configuration (domains, phishlet state, lures, proxy settings)
- `data.db` — BuntDB session database
- `crt/` — TLS certificate cache

## Architecture

### Startup Sequence (`main.go`)

On launch, `main.go` wires together all subsystems in order:
1. Load phishlet YAMLs from the phishlets directory into `Config`
2. Start `Nameserver` (built-in UDP DNS server)
3. Start `CertDb` (TLS cert manager via certmagic/ACME, or self-signed in developer mode)
4. Start `HttpProxy` (the MITM HTTPS server)
5. Hand control to `Terminal` (interactive CLI)

### Package Responsibilities

**`core/`** — all core logic lives here as a single Go package:

- **`http_proxy.go`** (`HttpProxy`): The heart of the tool. Built on a forked `goproxy` (`github.com/kgretzky/goproxy`). The `OnRequest` handler handles session creation/lookup, blacklist enforcement, lure matching, credential extraction from POST bodies, and URL rewriting from phishing→original domains. The `OnResponse` handler captures auth cookies and body tokens, performs URL rewriting original→phishing in response bodies, strips security headers (CSP, HSTS, X-Frame-Options), and injects JavaScript for session tracking and post-auth redirects. URL rewriting uses two large TLD-matching regexes (`MATCH_URL_REGEXP` / `MATCH_URL_REGEXP_WITHOUT_SCHEME`) to find and replace hostnames in response content.

- **`config.go`** (`Config`): Persisted state via `spf13/viper` as JSON. Manages phishlet enable/disable/hostname assignment, lures (URL paths that trigger new sessions), sub-phishlets (child phishlets derived from template phishlets with preset params), proxy upstream settings, blacklist mode, GoPhish integration settings, and the server domain/IP/port bindings. Config writes happen synchronously after every change.

- **`phishlet.go`** (`Phishlet`): Parses phishlet YAML files. A phishlet defines: `proxy_hosts` (subdomain mapping from original to phishing domain), `sub_filters` (regex search/replace rules applied to response bodies), `auth_tokens` (cookies/body fields/HTTP headers to capture), `credentials` (username/password capture patterns), `login` (target landing URL), `js_inject` (JavaScript to inject into specific pages), `intercept` (requests to short-circuit with a custom response), and `force_post` (POST body field overrides).

- **`session.go`** (`Session`): In-memory state for one active visitor. Tracks captured username, password, custom fields, cookie tokens (by domain+name), body tokens, HTTP header tokens, redirect URL, and completion state. `DoneSignal` is a channel closed when all required tokens are captured — this is used to unblock the dynamic redirect polling endpoint (`/s/<session_id>`).

- **`certdb.go`** (`CertDb`): TLS certificate management. In production mode uses `certmagic` with ACME (Let's Encrypt) via DNS-01 or TLS-ALPN-01 challenges. In developer mode generates self-signed certificates per-hostname on demand.

- **`nameserver.go`** (`Nameserver`): Authoritative UDP DNS server using `miekg/dns`. Answers A and NS queries for the configured base domain and its subdomains with the server's external IP.

- **`terminal.go`** (`Terminal`): Interactive CLI using `chzyer/readline`. Parses commands entered by the operator to configure phishlets, create lures, inspect sessions, configure the server, etc.

- **`blacklist.go`** (`Blacklist`): Loads IP/CIDR entries from `~/.evilginx/blacklist.txt`. Blacklist mode (`all`, `unauth`, `noadd`, `off`) controls whether unauthorized visitors are automatically added.

- **`gophish.go`** (`GoPhish`): Optional integration with a GoPhish instance. Reports email-open tracking, link-click events, and credential-capture events back to GoPhish via its REST API.

**`database/`** — BuntDB-backed persistence:

- **`database.go`**: Wraps `tidwall/buntdb`. Manages session CRUD (create, list, update username/password/tokens, delete).
- **`db_session.go`**: Session schema and BuntDB key layout.

**`parser/`** — Shell-like tokenizer used by `Terminal` to parse operator commands (handles quoting and escaping).

**`log/`** — Colored console logger with `Info`, `Warning`, `Error`, `Success`, `Fatal`, `Debug` levels.

### Phishlet YAML Format

Phishlets live in `./phishlets/*.yaml`. See `phishlets/example.yaml` for structure. Key fields:

```yaml
min_ver: '3.0.0'
proxy_hosts:
  - {phish_sub: 'login', orig_sub: 'login', domain: 'example.com', session: true, is_landing: true, auto_filter: true}
sub_filters:
  - {triggers_on: 'example.com', orig_sub: 'login', domain: 'example.com', search: 'regex', replace: 'replacement', mimes: ['text/html']}
auth_tokens:
  - domain: '.example.com'
    keys: ['session_cookie_name']
credentials:
  username:
    key: 'email'
    search: '(.*)'
    type: 'post'   # or 'json'
  password:
    key: 'password'
    search: '(.*)'
    type: 'post'
login:
  domain: 'login.example.com'
  path: '/signin'
```

`auto_filter: true` on a proxy host activates the automatic URL regex rewriting in responses for that host. Sub-phishlets (created via terminal `phishlets create`) inherit a parent phishlet's YAML with parameter substitution.

### Redirectors

HTML directories under `./redirectors/` can be assigned to lures. When a lure with a `redirector` set is hit, evilginx serves the `index.html` from that directory to the victim first, then later redirects them to the actual phishing URL. The HTML template supports `{lure_url_html}`, `{lure_url_js}`, and `{param_name}` substitutions. Path traversal outside the redirectors directory is explicitly blocked (`core/http_proxy.go`).

### Session Flow

1. Victim hits a lure URL → `OnRequest` creates a `Session`, sets a session tracking cookie (SHA-256-derived name), whitelists the victim's IP for 10 minutes.
2. Subsequent requests carry the session cookie → requests are proxied to the real site with hostnames rewritten to originals.
3. Response bodies have hostnames rewritten back to phishing domains; security headers stripped; JS injected.
4. Captured cookies/tokens accumulate in `Session.CookieTokens` etc.; when all required tokens are collected, `Session.Finish()` is called and data is persisted to BuntDB.
5. Post-capture, victim is JavaScript-redirected to `session.RedirectURL` (configurable per lure or phishlet).

## Module Path

The Go module is `github.com/kgretzky/evilginx2` (used in all internal imports). The goproxy dependency is replaced with a custom fork: `github.com/kgretzky/goproxy`.

## Dependency Management

Dependencies are vendored. Run `go mod vendor` after adding/changing dependencies. Build always uses `-mod=vendor`.

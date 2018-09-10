2018-09-07

* Developer mode added - start Evilginx with argument `-developer` and it will auto generate self-signed certificates for your phishing pages. Generated CA root certificate, that you can import into your certificate store, can be found at `$HOME/.evilginx/ca.crt`.
* Added `phishlets get-hosts` command to generate `/etc/hosts` local IP address mappings for any phishlet.
* Added auto-detection of `httpOnly` and `hostOnly` cookie flags.
* Completely rewrote authentication token detection and database storage (previously captured sessions will not load properly in this version).
* Phishlets now properly handle `.website.com` vs `website.com` cookie domains
* Added support for regular expressions in detecting authentication token cookie names. Use `regexp` flag with `,` separator in cookie name like this `_session_[0-9]{6},regexp`.
* Added `auth_urls` setting to phishlets where you can add URL path regular expressions that will be detected in HTTP requests. If matched, session will be considered authorized.
* Added support for regular expressions in detecting POST username and password key names. Use `regexp` flag with `,` separator in `key` under `user_regex` and `pass_regex` like this `login_[0-9]{8},regexp`.
* Fixed bug that prevented usage of empty subdomains in phishlets.

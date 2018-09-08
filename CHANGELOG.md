2018-09-07

* Developer mode added - start Evilginx with argument `-developer` and it will auto generate self-signed certificates for your phishing pages. Generated CA root certificate, that you can import into your certificate store, can be found at `$HOME/.evilginx/ca.crt`.
* Added `phishlets get-hosts` command to generate `/etc/hosts` local IP address mappings for any phishlet.
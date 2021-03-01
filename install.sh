wget https://golang.org/dl/go1.16.linux-amd64.tar.gz 

tar -C /usr/local -xzf go1.16.linux-amd64.tar.gz

echo "export PATH=$PATH:/usr/local/go/bin" >> $HOME/.profile
source $HOME/.profile
go version
git clone https://github.com/kgretzky/evilginx2.git
cd evilginx2
ls
go build
bigecho "Evilginx2 successfully installed!" 
bigecho "Usage:- cd evilginx2 -> ./evilginx2"

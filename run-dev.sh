#!/bin/bash
echo "[*] For Development Use."
echo "[*] Ensure you have rebuilt any changes with the 'make' command."
./build/evilginx -p ./phishlets -t ./redirectors -developer -debug

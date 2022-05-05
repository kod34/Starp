#!/bin/bash
sudo apt install macchanger xterm python3-pip -y
sudo pip3 install prettytable scapy
sudo cp $(readlink -f starp.py) ${PATH%%:*}/starp

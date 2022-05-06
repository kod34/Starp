#!/bin/bash
sudo apt install macchanger xterm python3-pip -y
sudo pip3 install -r requirements.txt
sudo cp $(readlink -f starp.py) ${PATH%%:*}/starp

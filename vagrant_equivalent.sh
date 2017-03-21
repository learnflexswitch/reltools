#!/bin/bash

#
#This is the equivlent script for creaing vagrant env
#

git clone https://github.com/learnflexswitch/vagrantFlexSwitchDev.git
sudo apt-get install -y build-essential fabric git wget
sudo apt-get install -y libnl-3-200 libnl-genl-3-200
wget https://storage.googleapis.com/golang/go1.5.3.linux-amd64.tar.gz
sudo apt-get install -y curl
curl -s https://packagecloud.io/install/repositories/github/git-lfs/script.deb.sh | sudo bash
sudo apt-get install -y git-lfs
sudo tar -C /usr/local -xzf go1.5.3.linux-amd64.tar.gz
mkdir git
cd git
echo "export GOPATH=~/git/snaproute:~/git/external:~/git/generated" >> /home/flex/.bashrc
echo "export PATH=$PATH:/usr/local/go/bin" >> /home/flex/.bashrc
echo "export SR_CODE_BASE=/home/flex/git" >> /home/flex/.bashrc
source /home/flex/.bashrc

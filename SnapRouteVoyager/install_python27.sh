##!/bin/bash

PWD=`pwd`
echo "${PWD}"
tar -xvzf Python-2.7.12.tgz -C /usr/src/
cd /usr/src/Python-2.7.12
sed -i "s/#readline/readline/g" Modules/Setup.dist
sed -i "s/#zlib/zlib/g" Modules/Setup.dist
./configure
make altinstall
cd ${PWD}

#!/bin/bash

install_cli_pkg() {
	which python2.7 > /dev/null
        if [ $? -ne 0 ]
        then
            ./install_python27.sh > /dev/null 2>&1 &
            PID=$!
            echo "Installing Python 2.7 THIS MAY TAKE A WHILE, PLEASE BE PATIENT WHILE ______ IS RUNNING..."
            printf "["
                # While process is running...
                while kill -0 $PID 2> /dev/null; do
                        printf  "▓"
                        sleep 5
                done
                printf "] done!"
        fi
    python cliInstaller.py --path="${1}"
}

install_flexswitch_voyager() {
    rpmName=${1}
	fSRPM=$(ls | grep ${rpmName})
    rpm -e --justdb --nodeps ${rpmName}
    rm -rf /opt/flexswitch
    rm -rf /etc/flexswitch
	rm -rf /etc/init.d/flexswitch*
    rpm -Uvh ${fSRPM}
}

install_flexswitch() {
	echo "Not supported"
}

if [ "${1}" == "flexswitch-voyager" ]
then
    /opt/flexswitch/flexswitch --op=stop
    redis-cli flushdb
    /etc/init.d/redis stop
    ./install_centos_dependency.sh
    ln -sf /etc/init.d/redis /etc/rc3.d/S80redis
    /etc/init.d/redis start
    /etc/init.d/rsyslog start
    install_flexswitch_voyager flexswitch-voyager
    chkconfig --level 345 flexswitch on
    /opt/flexswitch/flexswitch --op=start
elif [ "${1}" == "flexswitch" ]
then
	install_flexswitch
elif [ "${1}" == "flexswitchCli" ]
then
    install_cli_pkg "${2}"
else
	echo "Usage: ./install.sh <Platform>"
	echo "Platform: flexswitch, flexswitch-voyager"
fi

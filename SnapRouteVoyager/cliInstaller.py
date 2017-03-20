import os
import subprocess
from optparse import OptionParser

PKG_NAME = 'cliPkg.tar'

def executeCommands(commands):
    for cmd in commands:
        print 'Executing cmd : ', cmd
        process = subprocess.Popen(cmd.split(), stdout=subprocess.PIPE)
        out, err = process.communicate()
        if err:
            print 'Failed when executing : ', cmd

if __name__ == '__main__':
    parser = OptionParser()
    parser.add_option("-p", "--path",
            dest="cliInstallDir",
            action="store",
            help="Directory to use for CLI installation")
    (options, args) = parser.parse_args()
    executeCommands(['tar -xvf ' + PKG_NAME + ' -C ' + options.cliInstallDir + ' --warning=no-timestamp'])

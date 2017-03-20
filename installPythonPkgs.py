#!/usr/bin/env python
import os
from optparse import OptionParser
import syslog

if __name__=="__main__":
    parser = OptionParser()

    parser.add_option("-d", "--dir", 
                      dest="directory",
                      default="/opt/flexswitch",
                      action='store',
                      help="Directory where the python modules located")

    parser.add_option("-o", "--op", 
                      dest="op",
                      default="install",
                      action='store',
                      help="Operation (install/uninstall) ")

    (opts, args) = parser.parse_args()
    baseDir = opts.directory if opts.directory.endswith('/') else opts.directory+'/'
    op = opts.op
    bases = ['setuptools-28.2.0', 'urllib3-1.16']
    if op != 'uninstall' and os.path.exists(baseDir + 'setuptools-28.2.0'):
        os.chdir(baseDir + 'setuptools-28.2.0')
        os.system('python bootstrap.py')

    pkgDirs = bases + [x for x in os.listdir(baseDir) if os.path.isdir(baseDir +x) if x not in bases]
    for pkg in pkgDirs:
        if os.path.exists(baseDir + pkg + '/setup.py'):
            os.chdir(baseDir + pkg)
            os.system('python setup.py  %s' %(op))


import os
import subprocess
from optparse import OptionParser
from heapq import merge
import sys
import json


SNAP_ROUTE_SRC  = '/snaproute/src/'
BUILD_INFO_FILE = 'buildInfo.json'
SRC_INFO_FILE   = 'setupInfo.json'

def executeCommand (command) :
    out = ''
    if type(command) != list:
        command = [ command]
    for cmd in command:
        process = subprocess.Popen(cmd.split(), stdout=subprocess.PIPE)
        out,err = process.communicate()
    return out

class repo (object):
    def __init__ (self, base, repoName):
        self.name = repoName
        self.base = base
        self.repoDir = base + '/snaproute/src/'

    def writeRepoInfo (self) :
        os.chdir(self.repoDir + self.name)
        op = executeCommand('git show')
        gitHash = ''
        timeStamp = ''
        branch = ''
        for line in op.split('\n'):
            if 'commit' in line.split():
                gitHash = line.split()[1]
            elif 'Date:' in line.split():
                timeStamp = ' '.join(line.split()[1:])

        branch = executeCommand('git rev-parse --abbrev-ref HEAD')
        repoInfo = {'Name' : self.name,
                    'Sha1' : gitHash,
                    'Time' : timeStamp,
                    'Branch' : branch.rstrip('\n')
                    }
        return repoInfo

if __name__ == '__main__':
    repos = []
    baseDir = os.getenv('SR_CODE_BASE',None)
    if not baseDir:
        print 'Environment variable SR_CODE_BASE is not set'

    srcFile = baseDir + '/reltools/' + SRC_INFO_FILE
    repoPublicList = []
    repoPrivateList = []
    with open(srcFile) as infoFd:
	info = json.load(infoFd)
	for rp in info['PublicRepos']:
	    repoPublicList.append(rp)

    with open(srcFile) as infoFd:
	info = json.load(infoFd)
	for rp in info['PrivateRepos']:
	    repoPrivateList.append(rp)

    repoList = list(set(repoPrivateList + repoPublicList))
    for rp in repoList:
	if os.path.isdir(baseDir + "/snaproute/src/" + rp):
		repos.append(repo(baseDir, rp))

    reposInfoList = []
    with open(baseDir + "/reltools/" + BUILD_INFO_FILE, 'w') as bldFile:
        for rp in repos:
            reposInfoList.append(rp.writeRepoInfo())
        json.dump(reposInfoList, bldFile, indent=4, separators=(',', ': '), sort_keys=False)


#!/usr/bin/python
import os 
import json
import getpass
from gitClient import GitHubClient

repoInfoFile = '/reltools/setupInfo.json'
if __name__ == '__main__':
    baseDir = os.environ.get('SR_CODE_BASE', None)
    if baseDir:
        repos = []
        with open(baseDir + repoInfoFile) as dataFile:
            srcInfo = json.load(dataFile)
            repos = srcInfo['PrivateRepos'] + ['reltools']
        
        usrName = raw_input('Enter github user name: ')
        passwd = getpass.getpass('Password: ')
        branchName = raw_input('Enter Branch name: ')
        for repo in repos:
            print 'Making branch %s on Repo %s' %(repo, branchName)
            clnt = GitHubClient(usrName, passwd)
            print clnt.createBranch('SnapRoute', repo, 'master', branchName)

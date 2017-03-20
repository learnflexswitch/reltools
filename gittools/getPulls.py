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
        clnt = GitHubClient(usrName, passwd)
        for repo in repos:
            clnt.getPullRequestsList('SnapRoute', repo)

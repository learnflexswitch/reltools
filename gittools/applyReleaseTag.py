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
        tagName = raw_input('Name of the tag: ')
        relName = raw_input('Name of the release: ')
        branch = raw_input('Branch name [stable]: ') or 'stable' 
        description = raw_input('Description: ') 
        isDraft = raw_input('Draft[y] :') or 'y'
        isPrerel = raw_input('Pre-release[y] :') or 'y'
        if isDraft in ['y', 'Y', 'YES', 'yes']:
            isDraft = True
        else:
            isDraft = False 

        if isPrerel in ['y', 'Y', 'YES', 'yes']:
            isPrerel = True
        else:
            isPrerel = False 
        for repo in repos:
            print 'Applying tag on %s' %(repo)
            clnt = GitHubClient(usrName, passwd)
            #clnt.getReleases('SnapRoute', repo)
            print clnt.applyReleaseTag('SnapRoute', repo, branch, tagName, relName, description, isDraft, isPrerel)

import os
from fabric.api import local, run, env
from fabric.context_managers import lcd
from fabric.operations import prompt
from fabric.context_managers import settings

env.use_ssh_config = True
gSrRepos = ['asicd', 'l2', 'l3','config', 'utils','infra', 'flexSdk', 'apps', 'reltools', 'models', 'docs', 'test', 'opticd']
def mergeRepos (branch=None, comp=None):
    global gSrRepos
    print 'Fetching Snaproute repositories dependencies....'
    srRepos = gSrRepos
    if comp != None :
        srRepos = [comp] 

    for repo in srRepos:
        cmds = ['git checkout -b %s origin/%s' %(branch, branch),
                'git merge master',
                'git push origin %s' %(branch)
                ]
        local('mkdir -p tmp')
        with lcd('tmp'):
            local('git clone '+ 'https://github.com/snaproute/' + repo + '.git')
            with lcd(repo):
                print '## Merging repo %s' %(repo)
                for cmd in cmds:
                    print 'Executing Command %s' %(cmd)
                    local(cmd)

def mergeIntoMaster(branch=None, comp=None):
    global gSrRepos
    print 'Fetching Snaproute repositories dependencies....'
    srRepos = gSrRepos
    if comp != None :
        srRepos = [comp] 

    for repo in srRepos:
        cmds = ['git checkout %s' %('master'),
                'git remote add upstream https://github.com/snaproute/%s.git' %(repo),
                'git pull',
                'git fetch upstream',
                'git merge upstream/%s' %(branch),
                'git push origin'
                ]
        local('mkdir -p tmp')
        with lcd('tmp'):
            local('git clone '+ 'https://github.com/snaproute/' + repo + '.git')
            with lcd(repo):
                print '## Merging repo %s' %(repo)
                for cmd in cmds:
                    print 'Executing Command %s' %(cmd)
                    local(cmd)

def push(comp=None):
    global gSrRepos
    srRepos = gSrRepos
    if comp != None :
        srRepos = [comp]

    for repo in srRepos:
        print 'Pushing repo %s'  %(repo)
        cmds = ['git push origin']
        with lcd('tmp/'+repo):
            for cmd in cmds:
                print 'Pushing repo %s'  %(repo)
                local(cmd)


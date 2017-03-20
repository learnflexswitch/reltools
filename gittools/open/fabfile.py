import os
from fabric.api import local, run, env
from fabric.context_managers import lcd
from fabric.operations import prompt
from fabric.context_managers import settings

env.use_ssh_config = True
gSrRepos = ['l2', 'l3','utils', 'config', 'infra', 'flexSdk', 'apps', 'reltools', 'models', 'docs']
gBranches = ['rel_1.x_ga']
def syncRepo( comp = None):
    global gSrRepos
    global gBranches
    srRepos = gSrRepos
    if comp != None :
        srRepos = [comp]
    local('mkdir -p tmp')
    with lcd('tmp'):
        for repo in srRepos:
            print '## Working on Repo %s' %(repo)
            for branch in gBranches:
                '## Working on Branch %s' %(branch)
                with  lcd(repo):
                    cmds = [ 'git checkout master',
                             'git fetch upstream',
                             'git merge upstream/rel_1.x_ga',
                             'git push origin'
                             ]

                    for cmd in cmds:
                        local(cmd)

def fetchRepos (comp=None):
    global gSrRepos
    global gBranches
    print 'Fetching Snaproute repositories dependencies....'
    srRepos = gSrRepos
    if comp != None :
        srRepos = [comp]

    local('mkdir -p tmp')
    with lcd('tmp'):
        for repo in srRepos:
            local('git clone '+ 'https://github.com/OpenSnaproute/' + repo + '.git')
            with lcd(repo):
                local('git remote add upstream https://github.com/SnapRoute/' +  repo + '.git')
                local('git fetch upstream')

def mergeDocs ():
    local('git clone '+ 'https://github.com/OpenSnaproute/' + 'docs' + '.git')
    with lcd('docs'):
        cmds = [ 'git remote add upstream https://github.com/SnapRoute/docs.git',
                 'git fetch upstream',
                 'git checkout -b gh-pages origin/gh-pages',
                 'git merge upstream/gh-pages'
                 ]

        for cmd in cmds:
            local(cmd)

def syncAll (comp = None):
    fetchRepos(comp)
    syncRepo(comp)

import os 
import json
from fabric.api import run, env, local
from fabric.context_managers import lcd
from json import dumps, load
from optparse import OptionParser

SETUPFILE = 'setupInfo.json'
PKGFILE = 'pkgInfo.json'

if __name__ == '__main__':

    parser = OptionParser()

    parser.add_option("-e", "--edit", 
                      dest="edit",
                      action='store_true',
                      default=False,
                      help="Edit revision")
    
    parser.add_option("-b", "--branch", 
                      dest="branch",
                      action='store',
                      default="rel_1.x_ga",
                      help="Branch Version for which you want to do the build")

    (options, args) = parser.parse_args()
    
    with open(SETUPFILE) as fd:
        info = json.load(fd)
    repoList = info['PrivateRepos'] + ['reltools']
    baseDir = os.getenv('SR_CODE_BASE','~/git/')
    
    for repo in  repoList:
	print "path of repo %s is : %s/snaproute/src/%s" %(baseDir, repo, repo)
        if repo == 'reltools':
            srcPath = baseDir + '/'
        else:
            srcPath = baseDir + '/snaproute/src/'
	with lcd (srcPath + repo):
            local ('git reset --hard')
            try:
                local ('git checkout %s' %(options.branch))
            except:
                local ('git checkout -b %s remotes/upstream/%s' %(options.branch, options.branch))
            local ('git fetch upstream %s' %(options.branch))
            local ('git merge upstream/%s' %(options.branch))

	if repo == 'asicd' :
            with lcd (baseDir + '/snaproute/src/'+repo):
                local('git lfs install')
                local('git lfs fetch')
                local('git lfs checkout')

    with open(PKGFILE) as pkg_info:
	pk_info = json.load(pkg_info)

    if options.edit != False:
        pk_info["changeindex"] = str(int(pk_info["changeindex"]) + 1)
    
    with open(PKGFILE, "w+") as fd_pkg:
        json.dump(pk_info, fd_pkg, indent=4,  sort_keys=True)

    if options.edit != False:
        with lcd(baseDir + '/reltools/'):
            local('git add %s ' %(PKGFILE))
            local('git commit -m \"Bumping up the release number\"') 
            local('git push origin %s' % (options.branch)) 


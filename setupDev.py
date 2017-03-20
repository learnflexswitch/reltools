import os
import subprocess
from optparse import OptionParser
import sys
import json
import shlex

thrift_version = '0.9.3'
thrift_pkg_name = 'thrift-'+thrift_version 
thrift_tar = thrift_pkg_name +'.tar.gz'

pcap_version = '1.6.2-2'

TMP_DIR = ".tmp"
SNAP_ROUTE_SRC = '/snaproute/src/'
EXTERNAL_SRC = '/external/src/'
GENERATED_SRC = '/generated/src/'

gHomeDir = None
gDryRun =  False

gitProtocol = "https"

def executeCommandV2(command):
    out = ''
    if type(command) != list:
        command = [ command]
    for cmd in command:
        if gDryRun :
            print cmd
        else:
            print cmd
            args = shlex.split(cmd)
            process = subprocess.Popen(args)
            out,err = process.communicate()
    return out


def executeCommand (command) :
    out = ''
    if type(command) != list:
        command = [ command]
    for cmd in command:
        if gDryRun :
            print cmd
        else:
            process = subprocess.Popen(cmd.split(), stdout=subprocess.PIPE)
            out,err = process.communicate()
    return out

def downloadThrift() :
    print 'Downloading Thrift'
    command = []
    command.append('mkdir -p '+TMP_DIR)
    executeCommand(command)

    command = []
    command.append('wget -O '+ TMP_DIR + '/' +thrift_tar+ ' '+ 
                    'http://apache.arvixe.com/thrift/0.9.3/thrift-0.9.3.tar.gz')
    executeCommand(command)

def installGoPacketDependencies ():
    command = []
    command.append('sudo apt-get install libpcap-dev')
    executeCommand(command)

def installNanoMsgLib(dir) :
    print 'Installing nanomsg dir - ', dir
    os.chdir(dir)
    cmdList = ['sudo apt-get install libtool',
               'libtoolize',
               './autogen.sh',
               './configure',
               'make',
               'sudo make install',
              ]
    executeCommand(cmdList)

def verifyThriftInstallation():
    #return True
    command = []
    command.append('thrift -version')
    #'Thrift version 0.9.3'
    resp = ""
    try:
        resp = executeCommand(command)
    except:
        pass
    print 'Thrift version check returned %s' %(resp)
    if thrift_version in resp:
        return True
    else:
        return False

def installThrift() :

    if True == verifyThriftInstallation():
        print ' Thrift already exists returning'
        return

    downloadThrift()
    os.chdir(TMP_DIR)
    command = 'tar -xvf '+ thrift_tar
    executeCommand(command)

    os.chdir(thrift_pkg_name)

    command = './configure'
    executeCommand(command)

    command = 'make'
    executeCommand(command)

    command = 'sudo make install'
    executeCommand(command)

    if False== verifyThriftInstallation():
        print ' Thrift Installation failed'
        return

def installThriftDependencies ():
    command = []
    command.append('sudo apt-get install libboost-dev libboost-test-dev libboost-program-options-dev libboost-system-dev libboost-filesystem-dev libevent-dev automake libtool flex bison pkg-config g++ libssl-dev ant')
    executeCommand(command)

def installPythonDependencies ():
    pythonPackages = ['python-dev',
                      'python-bitarray',
                      'python-paramiko',
                      'python-netaddr'
                     ]
    for pkg in pythonPackages:
        command = []
        command.append('sudo apt-get install ' + pkg)
        executeCommand(command)


def installPkgDependencies ():
    command = []
    command.append('sudo apt-get install fakeroot dh-make')
    executeCommand(command)


def cloneGitRepo (repourl, repo, dirloc):
    os.chdir(dirloc)
    if not (os.path.exists(dirloc + repo)  and os.path.isdir(dirloc + repo)):
        command = 'git clone '+ repourl
        executeCommand(command)

def gitRepoSyncToTag(dirloc, tag):
    os.chdir(dirloc)
    command = 'git checkout tags/'+ tag
    executeCommand(command)
    
def setRemoteUpstream (repoUrl):
    command = 'git remote add upstream ' + repoUrl
    executeCommand(command)
    commandsToSync = ['git fetch upstream',
                      'git checkout master',
                      'git merge upstream/master']
    for cmd in commandsToSync:
        executeCommand(cmd)

def getGolangExternalDependencies(repourl, dirloc):
    os.chdir(dirloc)
    command = 'git clone '+ repourl
    executeCommand(command)

def createDirectoryStructure() :
    dirs = [SNAP_ROUTE_SRC,EXTERNAL_SRC, GENERATED_SRC]
    for everydir in dirs:
        command = 'mkdir -p '+ gHomeDir + everydir 
        executeCommand(command)

def getExternalGoDeps() :
    externalGoDeps = [
                     { 'repo'      : 'thrift',
                       'reltag'    : '0.9.3',
                       'renamesrc' : 'thrift',
                       'renamedst' : 'git.apache.org/thrift.git'
                     },
                     { 'repo'       : 'mux',
                       'renamesrc'  : 'mux',
                       'renamedst'  : 'github.com/gorilla/'
                     },
                     { 'repo'       : 'context',
                       'renamesrc'  : 'context',
                       'renamedst'  : 'github.com/gorilla/'
                     },
                     { 'repo'        : 'gopacket',
                       'renamesrc'   : 'gopacket',
                       'renamedst'   : 'github.com/google/'
                     },
                     { 'repo'        : 'go-sqlite3',
                       'reltag'      : 'v1.1.0',
                       'renamesrc'   : 'go-sqlite3',
                       'renamedst'   : 'github.com/mattn/'
                     },
                     { 'repo'        : 'pyang',
                       #'renamesrc'   : 'pyang',
                     },
                     { 'repo'        : 'openconfig',
                       #'renamesrc'   : 'pyang',
                     },
                     { 'repo'        : 'nanomsg',
                       'renamesrc'   : 'nanomsg',
                       'renamedst'   : 'github.com/nanomsg/'
                     },
                     { 'repo'        : 'go-nanomsg',
                       'renamesrc'   : 'go-nanomsg',
                       'renamedst'   : 'github.com/op/'
                     },
                     { 'repo'        : 'netlink',
                       'renamesrc'   : 'netlink',
                       'renamedst'   : 'github.com/vishvananda/netlink'
                     },
                     { 'repo'        : 'netns',
                       'renamesrc'   : 'netns',
                       'renamedst'   : 'github.com/vishvananda/netns'
                     },

                     { 'repo'        : 'gouuid',
                       'renamesrc'   : 'gouuid',
                       'renamedst'   : 'github.com/nu7hatch/gouuid'
                     },
                     { 'repo'        : 'net',
                       'renamesrc'   : 'net',
                       'renamedst'   : 'golang.org/x/net'
                     },
                     { 'repo'        : 'redigo',
                       'renamesrc'   : 'redigo',
                       'renamedst'   : 'github.com/garyburd/redigo'
                     },
                     {
                        'repo'      : 'libovsdb',
                        'renamesrc' : 'libovsdb',
                        'renamedst' : 'github.com/socketplane/libovsdb'
                     },
                     {
                        'repo'      : 'netfilter',
                        'renamesrc' : 'netfilter',
                        'renamedst' : 'github.com/netfilter'
                     },
                     ]

    dirLocation = gHomeDir + EXTERNAL_SRC 
    for dep in externalGoDeps:
        #if dep['repo'] == 'netlink':
        #    import ipdb;ipdb.set_trace()
        if gitProtocol == "ssh":
            repoUrl = 'git@github.com:SnapRoute/'+ dep['repo']
        else:
            repoUrl = 'https://github.com/SnapRoute/'+ dep['repo']
        dstDir =  dep['renamedst'] if dep.has_key('renamedst') else ''
        dirToMake = dstDir 
        #if dstDir == '' or (dstDir != '' and not (os.path.isdir(dirLocation + dstDir) and os.path.exists(dirLocation + dstDir))):
        if dstDir == '' or (dstDir != '' and not (os.path.exists(dirLocation + dstDir + '/' + dep['repo']))):
            cloneGitRepo ( repoUrl ,dep['repo'], dirLocation)
            if dep.has_key('reltag'):
                gitRepoSyncToTag(dirLocation+dep['repo'], dep['reltag'])

            if not dstDir.endswith('/'):
                dirToMake = dstDir[0:dstDir.rfind('/')]
            os.chdir(dirLocation)
            if dirToMake:
                cmd  =  'mkdir -p ' + dirToMake
                executeCommand(cmd)
            if dep.has_key('renamesrc'):
                cmd = 'mv ' + dirLocation + dep['renamesrc']+ ' ' + dirLocation + dep['renamedst']
                executeCommand(cmd)
            if dep['repo'] == 'nanomsg':
                installNanoMsgLib(dirLocation + dep['renamedst'] + dep['renamesrc'])
            if dep['repo'] == 'netfilter':
                setupIpTablelib()
                

def cloneSnapRouteGitRepos( gitReposToClone = None):
    if gitProtocol == "ssh":
        userRepoPrefix   = 'git@github.com:'+gUserName+'/'
        remoteRepoPrefix = 'git@github.com:'+ 'SnapRoute/'
    else:
        userRepoPrefix   = 'https://github.com/'+gUserName+'/'
        remoteRepoPrefix = 'https://github.com/'+ 'SnapRoute/'
    dirLocation      = gHomeDir + SNAP_ROUTE_SRC

    if not gitReposToClone :
        gitReposToClone = []
        with open('setupInfo.json') as data_file:
            data = json.load(data_file)                                                                                 
            gitReposToClone = data['PrivateRepos']

    for repo in gitReposToClone:
        cloneGitRepo ( userRepoPrefix + repo, repo, dirLocation)
        os.chdir(repo)
        setRemoteUpstream (remoteRepoPrefix +repo+'.git')

def setupMakefileLink ():
    if not os.path.isfile(gHomeDir + SNAP_ROUTE_SRC +'Makefile' ):
        cmd = 'ln -s ' + gHomeDir +  '/reltools/Makefile '+ gHomeDir + SNAP_ROUTE_SRC +'Makefile'
        executeCommand(cmd)

def setupGitCredentialCache ():
    cmd = 'git config --global credential.helper \"cache --timeout=3600\"'
    os.system(cmd)

def setupOpenNslLibLink ():
    libLocation = gHomeDir + SNAP_ROUTE_SRC + 'asicd/pluginManager/opennsl/'
    if not os.path.isfile(libLocation + 'libopennsl.so'):
        cmd = 'ln -s ' + libLocation + 'libopennsl.so.1 ' + libLocation + 'libopennsl.so'
        executeCommand(cmd)

def setupIpTablelib ():
    nfLoc = gHomeDir + EXTERNAL_SRC + 'github.com/netfilter/'
    if gitProtocol == "ssh":
        repoUrl = 'git@github.com:'+ 'SnapRoute/netfilter'
    else:
        repoUrl= 'https://github.com/'+ 'SnapRoute/netfilter'
    print nfLoc
    print repoUrl
    cloneGitRepo ( repoUrl ,'netfilter', gHomeDir + EXTERNAL_SRC + 'github.com/')
    libipDir = 'libiptables'
    allLibs = ['libmnl', 'libnftnl', 'iptables']
    os.chdir(nfLoc)
    command = []
    command.append('mkdir -p '+ libipDir)
    executeCommand(command)
    prefixDir = nfLoc + libipDir
    cflagsDir = nfLoc + libipDir + "/include"
    ldflagsDir = nfLoc + libipDir + "/lib"

    for lib in allLibs:
        os.chdir(nfLoc + lib)
        cmd = []
        cmd.append('./autogen.sh')
        if lib == 'libmnl':
            cmd.append('./configure --prefix=\"' + prefixDir + '\"')
        elif lib == 'libnftnl':
            os.environ["LIBMNL_CFLAGS"]= nfLoc + libipDir + "/include/libmnl"
            os.environ["LIBMNL_LIBS"]= nfLoc + libipDir + "/lib/pkgconfig"
            cmd.append('./configure --prefix="' + prefixDir + '" CFLAGS="-I' + cflagsDir + '" LDFLAGS="-L' + ldflagsDir +'"')
        elif lib == 'iptables':
            cmd.append('./configure --prefix="' + prefixDir + '" CFLAGS="-I' + cflagsDir + '" LDFLAGS="-L' + ldflagsDir +'" LIBS=\"-lmnl -lnftnl\"')
        cmd.append('make')
        cmd.append('make install')
        executeCommandV2(cmd)

if __name__ == '__main__':
    parser = OptionParser()

    parser.add_option("-r", "--repo", 
                      dest="specific_repo",
                      action='store',
                      help="Only specific Snaproute repo")

    parser.add_option("-s", "--snaproute", 
                      dest="sr_repos",
                      action='store_false',
                      help="Only Snaproute repos")

    parser.add_option("-p", "--python", 
                      dest="py_pkgs",
                      action='store_true',
                      help="Only Python Modules")

    parser.add_option("-e", "--external", 
                      dest="ex_repos",
                      action='store_true',
                      help="Only External repos")

    parser.add_option("-u", "--update", 
                      dest="update",
                      action='store_true',
                      help="Update the new additions")

    parser.add_option("-g", "--gitprotocol", 
                      dest="git_proto",
                      action='store',
                      help="Git protocol ssh/https")


    (options, args) = parser.parse_args()

    gUserName =  raw_input('Please Enter github username:')
    gHomeDir = os.path.dirname(os.getcwd())
    print '### Anchor Directory is %s' %(gHomeDir)

    if options.git_proto == "ssh":
        print '### set git protocol to ssh'
        gitProtocol = "ssh"

    todo = ['external', 'snaproute', 'specific_repo', 'python', 'netfilter']
    if options.sr_repos or options.specific_repo:
        todo = ['snaproute']

    if options.ex_repos:
        todo = ['external']

    if options.py_pkgs:
        todo = ['python']
    
    if options.update:
        todo = ['update']

    if len(todo) > 1:
        createDirectoryStructure()
        setupMakefileLink()

        if 'python' in todo:
            installPythonDependencies()
        installPkgDependencies()

        if False == verifyThriftInstallation():
            installThriftDependencies()
            installThrift()
        else:
            print ' Thrift already exists'
                    
        installGoPacketDependencies()

        setupGitCredentialCache()
   
    if 'snaproute' in todo:
        reposList = None
        if options.specific_repo:
            reposList = [options.specific_repo]
        cloneSnapRouteGitRepos(reposList)
    
    if 'external' in todo:
        getExternalGoDeps()
    
    if 'update' in todo:
        setupIpTablelib()
        
    setupOpenNslLibLink()

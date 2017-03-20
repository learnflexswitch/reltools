import os
from shutil import copyfile
# input files
PROLOGUE_FILE = 'samples/nginx_conf_prologue.txt'
EPILOGUE_FILE = 'samples/nginx_conf_epilogue.txt'
NGINX_SA_DEFAULT_TXT_FILE = 'samples/sitesAvailableDefault.txt'
NGINX_LDAP_CONF_FILE = 'samples/pamNginxLdapConf.txt'

# output files
NGINX_CONF_FILE_SRC = 'samples/nginx/nginx.conf'
NGINX_SA_DEFAULT_FILE_SRC = 'samples/nginx/sites-available/default'
PAMD_NGINX_CONF_FILE_SRC = 'samples/pam.d/nginx'

# destination files
NGINX_CONF_FILE_DST = '/etc/nginx/nginx.conf'
NGINX_SA_DEFAULT_FILE_DST = '/etc/nginx/sites-available/default'
PAMD_NGINX_CONF_FILE_DST = '/etc/pam.d/nginx'

configDict = {}
def editConfig():
    nginxConfDir = 'samples/nginx/'
    nginxSitesAvailDir = 'samples/nginx/sites-available/'
    if not os.path.exists(nginxConfDir):
        os.makedirs(nginxConfDir)
        os.makedirs(nginxSitesAvailDir)
    with open(NGINX_CONF_FILE_SRC, 'w')  as confFile:
        with open(PROLOGUE_FILE, 'r') as prologue:
            confFile.writelines(prologue.readlines())   
        line =  '            proxy_pass  http://localhost:%s;' % (configDict['proxy_pass'])
        confFile.write(line)
        with open(EPILOGUE_FILE , 'r') as epilogue:
            confFile.writelines(epilogue.readlines())   

    with open(NGINX_SA_DEFAULT_FILE_SRC, 'w')  as defaultSiteFile:
        with open(NGINX_SA_DEFAULT_TXT_FILE, 'r') as defaultSiteTextFile:
            defaultSiteFile.writelines(defaultSiteTextFile.readlines())   
        
def populateConfig():
    global configDict
    apiPort = raw_input('Enter API port : ')
    configDict['proxy_pass'] = apiPort
    authProto = raw_input('Authentication type : (local/ldap) ')
    configDict['auth_proto'] = authProto

def createPamNginxConfFile():
    pamdNginxConfDir = 'samples/pam.d/'
    if not os.path.exists(pamdNginxConfDir):
        os.makedirs(pamdNginxConfDir)
    with open(PAMD_NGINX_CONF_FILE_SRC, 'w') as pamdNginxFile:
        if configDict['auth_proto'] is 'local':
            line = '@include common-auth'
            pamdNginxFile.writelines(line)
        elif configDict['auth_proto'] is 'ldap':
            with open(NGINX_LDAP_CONF_FILE, 'r') as ldapConfFile:
                pamdNginxFile.writelines(ldapConfFile.readlines())
    copyfile(PAMD_NGINX_CONF_FILE_SRC, PAMD_NGINX_CONF_FILE_DST)

def createSslKeys():
    sslKeysDir = '/etc/nginx/ssl'
    if not os.path.exists(sslKeysDir):
        os.makedirs(sslKeysDir)
    sslKeysCmd = 'openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout /etc/nginx/ssl/server.key -out /etc/nginx/ssl/server.crt'
    os.system(sslKeysCmd)

def createNginxConfFiles():
    copyfile(NGINX_CONF_FILE_SRC, NGINX_CONF_FILE_DST)
    copyfile(NGINX_SA_DEFAULT_FILE_SRC, NGINX_SA_DEFAULT_FILE_DST)

def restartNginx():
    cmd = 'service nginx restart'
    os.system(cmd)

if __name__ == '__main__':
    populateConfig()
    editConfig()
    createPamNginxConfFile()
    createSslKeys()
    createNginxConfFiles()
    restartNginx()


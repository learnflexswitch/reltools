#!/usr/bin/env python
import os
import sys
from optparse import OptionParser

#Global variables
srBase = os.environ.get('SR_CODE_BASE', None)
srCodeBase = ""
daemonDirectory = ""
rpcDirectory = ""
serverDirectory = ""
repoName = ""
moduleName = ""
daemonName = ""
objectFileName = ""
copyrightFile = ""

#Create directory structure for the new daemon
def createDirectoryStructure(dmnName, modName, rName, objFile):
    global srBase, srCodeBase, daemonDirectory, rpcDirectory, serverDirectory
    global repoName, moduleName, daemonName, objectFileName, copyrightFile
    daemonDirectory = srCodeBase + rName + "/" + modName + "/"
    rpcDirectory = daemonDirectory + "rpc/"
    serverDirectory = daemonDirectory + "server/"
    repoName = rName
    moduleName = modName
    daemonName = dmnName
    objectFileName = objFile
    copyrightFile = srBase + "reltools/codegentools/copyright.txt"

    if not os.path.exists(daemonDirectory):
        os.makedirs(daemonDirectory)
    else:
        print(daemonDirectory, "exists")

    if not os.path.exists(rpcDirectory):
        os.makedirs(rpcDirectory)
    else:
        print(rpcDirectory, "exists")

    if not os.path.exists(serverDirectory):
        os.makedirs(serverDirectory)
    else:
        print(serverDirectory, "exists")


def writeCopyrightBlock(fd):
    global copyrightFile
    for line in open(copyrightFile, 'r'):
        fd.write(line)



def writeMainFile():
    global daemonDirectory, repoName, daemonName, moduleName
    fileName = daemonDirectory + "main.go"
    mainfd = open(fileName, 'w+')
    writeCopyrightBlock(mainfd)
    mainfd.write("\npackage main\n\n")
    if repoName == "":
        rpcImport = moduleName + "/rpc"
        serverImport = moduleName + "/server"
    else:
        rpcImport = repoName + "/" + moduleName + "/rpc"
        serverImport = repoName + "/" + moduleName + "/server"
    mainfd.write("""import (\n    "%s"\n    "%s"\n    "strconv"\n    "strings"\n    "utils/dmnBase"\n)\n\n""" % (rpcImport, serverImport))
    mainfd.write("""const (\n DMN_NAME = "%s"\n)\n\n""" % daemonName)
    mainfd.write("type Daemon struct {\n   *dmnBase.FSBaseDmn\n    daemonServer *server.DmnServer\n    rpcServer *rpc.RPCServer\n}\n\n")
    mainfd.write("var dmn Daemon\n\n")
    mainfd.write("""func main() {
        dmn.FSBaseDmn = dmnBase.NewBaseDmn(DMN_NAME, DMN_NAME)
        ok := dmn.Init()
        if !ok {
                panic("Daemon Base initialization failed for %s")
        }

        serverInitParams := &server.ServerInitParams{
                DmnName:   DMN_NAME,
                ParamsDir: dmn.ParamsDir,
                DbHdl:     dmn.DbHdl,
                Logger:    dmn.FSBaseDmn.Logger,
        }
        dmn.daemonServer = server.New%sServer(serverInitParams)
        go dmn.daemonServer.Serve()

        var rpcServerAddr string
        for _, value := range dmn.FSBaseDmn.ClientsList {
                if value.Name == strings.ToLower(DMN_NAME) {
                        rpcServerAddr = "localhost:" + strconv.Itoa(value.Port)
                        break
                }
        }
        if rpcServerAddr == "" {
                panic("Daemon %s is not part of the system profile")
        }
        dmn.rpcServer = rpc.NewRPCServer(rpcServerAddr, dmn.FSBaseDmn.Logger)

        dmn.StartKeepAlive()

        // Wait for server started msg before opening up RPC port to accept calls
        _ = <-dmn.daemonServer.InitCompleteCh

        //Start RPC server
        dmn.FSBaseDmn.Logger.Info("Daemon Server started for %s")
        dmn.rpcServer.Serve()
        panic("Daemon RPC Server terminated %s")
}\n""" % (daemonName, daemonName.upper(), daemonName, daemonName, daemonName))
    mainfd.close()


def writeRpcFile():
    global rpcDirectory, daemonName
    fileName = rpcDirectory + "rpc.go"
    rpcfd = open(fileName, 'w+')
    writeCopyrightBlock(rpcfd)
    rpcfd.write("\npackage rpc\n\n")
    rpcfd.write("""import (\n    "%s"\n    "git.apache.org/thrift.git/lib/go/thrift"\n    "utils/logging"\n)\n\n""" % daemonName)
    rpcfd.write("type rpcServiceHandler struct {\n    logger logging.LoggerIntf\n}\n\n")
    rpcfd.write("func newRPCServiceHandler(logger logging.LoggerIntf) *rpcServiceHandler {\n    return &rpcServiceHandler{\n        logger: logger,\n    }\n}\n\n")
    rpcfd.write("type RPCServer struct {\n    *thrift.TSimpleServer\n}\n\n")
    rpcfd.write("""func NewRPCServer(rpcAddr string, logger logging.LoggerIntf) *RPCServer {
        transport, err := thrift.NewTServerSocket(rpcAddr)
        if err != nil {
                panic(err)
        }
        handler := newRPCServiceHandler(logger)
        processor := %s.New%sServicesProcessor(handler)
        transportFactory := thrift.NewTBufferedTransportFactory(8192)
        protocolFactory := thrift.NewTBinaryProtocolFactoryDefault()
        server := thrift.NewTSimpleServer4(processor, transport, transportFactory, protocolFactory)
        return &RPCServer{
                TSimpleServer: server,
        }
}\n""" % (daemonName, daemonName.upper()))
    rpcfd.close()


def writeRcpHdlFunc(fd, obj, keyTypes, config, state):
    global daemonName
    if obj == "":
        return
    if config == True:
        fd.write("""func (rpcHdl *rpcServiceHandler) Create%s(cfg *%s.%s) (bool, error) {
        rpcHdl.logger.Info("Calling Create%s", cfg)
        return true, nil
}

func (rpcHdl *rpcServiceHandler) Update%s(oldCfg, newCfg *%s.%s, attrset []bool, op []*%s.PatchOpInfo) (bool, error) {
        rpcHdl.logger.Info("Calling Update%s", oldCfg, newCfg)
        return true, nil
}

func (rpcHdl rpcServiceHandler) Delete%s(cfg *%s.%s) (bool, error) {
        rpcHdl.logger.Info("Calling Delete%s", cfg)
        return true, nil
}\n\n""" % (obj, daemonName, obj, obj, obj, daemonName, obj, daemonName, obj, obj, daemonName, obj, obj))
    keyStr = ""
    i = 0
    for keyType in keyTypes:
        i = i+1
        keyStr = keyStr + "key%s %s" % (i, keyType)
        if i < len(keyTypes):
            keyStr = keyStr + ", "
    if state == True:
        fd.write("""func (rpcHdl *rpcServiceHandler) Get%s(%s) (obj *%s.%s, err error) {
        rpcHdl.logger.Info("Calling Get%s", key1)
        return obj, err
}

func (rpcHdl *rpcServiceHandler) GetBulk%s(fromIdx, count %s.Int) (*%s.%sGetInfo, error) {
        var getBulkInfo %s.%sGetInfo
        var err error
        //info, err := api.GetBulk%s(int(fromIdx), int(count))
        //getBulkInfo.StartIdx = fromIdx
        //getBulkInfo.EndIdx = %s.Int(info.EndIdx)
        //getBulkInfo.More = info.More
        //getBulkInfo.Count = %s.Int(len(info.List))
        // Fill in data, remember to convert back to thrift format
        return &getBulkInfo, err
}\n\n""" % (obj, keyStr, daemonName, obj, obj, obj, daemonName, daemonName, obj, daemonName, obj, obj, daemonName, daemonName))


def writeRpcHdlFile():
    global rpcDirectory, objectFileName, daemonName
    if objectFileName == "":
        return
    objFile = srCodeBase + "models/objects/" + objectFileName
    fileName = rpcDirectory + "rpcHdl.go"
    rpcfd = open(fileName, 'w+')
    writeCopyrightBlock(rpcfd)
    rpcfd.write("\npackage rpc\n\n")
    rpcfd.write("""import (
        "%s"
)\n\n""" % daemonName)
    import re
    objName = ""
    keyTypes = []
    for line in open(objFile, 'r'):
        if 'struct' in line:
            objLine = re.split('\s+', line)
            objName = objLine[1]
            configObj = False
            stateObj = False
            keyTypes = []
        if 'SNAPROUTE' in line:
            keyLine = re.split('\s+', line)
            keyTypes.append(keyLine[2])
            for word in keyLine:
                if 'ACCESS' in word:
                    if 'w' in word:
                        configObj = True
                    if 'r' in word:
                        stateObj = True
        if '}' in line:
            writeRcpHdlFunc(rpcfd, objName, keyTypes, configObj, stateObj)


def writeServerFile():
    global serverDirectory, daemonName
    fileName = serverDirectory + "server.go"
    serverfd = open(fileName, 'w+')
    writeCopyrightBlock(serverfd)
    serverfd.write("\npackage server\n\n")
    serverfd.write("""import (
        "utils/dbutils"
        "utils/keepalive"
        "utils/logging"
)\n\n""")
    serverfd.write("""type DmnServer struct {
        // store info related to server
        DbHdl          dbutils.DBIntf
        Logger         logging.LoggerIntf
        InitCompleteCh chan bool
}\n\n""")
    serverfd.write("""type ServerInitParams struct {
        DmnName     string
        ParamsDir   string
        CfgFileName string
        DbHdl       dbutils.DBIntf
        Logger      logging.LoggerIntf
}\n\n""")
    serverfd.write("""func New%sServer(initParams *ServerInitParams) *DmnServer {
        srvr := DmnServer{}
        srvr.DbHdl = initParams.DbHdl
        srvr.Logger = initParams.Logger
        srvr.InitCompleteCh = make(chan bool)

        // setup whatever you need for your server

        return &srvr
}\n\n""" % daemonName.upper())
    serverfd.write("""func (srvr *DmnServer) initServer() error {
        // initize the daemon server here
        return nil
}\n\n""")
    serverfd.write("""func (srvr *DmnServer) Serve() {
        srvr.Logger.Info("Server initialization started")
        err := srvr.initServer()
        if err != nil {
              panic(err)
        }
        daemonStatusListener := keepalive.InitDaemonStatusListener()
        if daemonStatusListener != nil {
                go daemonStatusListener.StartDaemonStatusListner()
        }
        srvr.InitCompleteCh <- true
        srvr.Logger.Info("Server initialization complete, starting cfg/state listerner")
        for {
                select {
                //case req := <-srvr.ReqChan:
                //      srvr.Logger.Info("Server request received - ", *req)
                //      srvr.handleRPCRequest(req)
                case daemonStatus := <-daemonStatusListener.DaemonStatusCh:
                        srvr.Logger.Info("Received daemon status: ", daemonStatus.Name, daemonStatus.Status)
                }
        }
}\n""")
    serverfd.close()


def writeMakeFile():
    global daemonDirectory, daemonName, repoName
    fileName = daemonDirectory + "Makefile"
    mkfd = open(fileName, 'w+')
    mkfd.write("""RM=rm -f
RMFORCE=rm -rf
DESTDIR=$(SR_CODE_BASE)/snaproute/src/out/bin
GENERATED_IPC=$(SR_CODE_BASE)/generated/src
IPC_GEN_CMD=thrift
SRCS=main.go
IPC_SRCS=rpc/%s.thrift
COMP_NAME=%s
GOLDFLAGS=-r /opt/flexswitch/sharedlib
all:exe
all:ipc exe
ipc:
\t$(IPC_GEN_CMD) -r --gen go -out $(GENERATED_IPC) $(IPC_SRCS)

exe: $(SRCS)
\tgo build -o $(DESTDIR)/$(COMP_NAME) -ldflags="$(GOLDFLAGS)" $(SRCS)
 
guard:
ifndef SR_CODE_BASE 
\t$(error SR_CODE_BASE is not set)
endif

install:
\t@echo "%s has no files to install"
clean:guard
\t$(RM) $(DESTDIR)/$(COMP_NAME)
\t$(RMFORCE) $(GENERATED_IPC)/$(COMP_NAME)\n""" % (daemonName, daemonName, daemonName))


if __name__ == "__main__":
    parser = OptionParser()

    parser.add_option("-d", "--daemon",
                      dest="daemon",
                      action="store",
                      help="Name of the daemon")

    parser.add_option("-m", "--module",
                      dest="module",
                      action="store",
                      help="Name of the module")

    parser.add_option("-r", "--repo",
                      dest="repo",
                      action="store",
                      help="Name of the repo this demon belongs to")

    parser.add_option("-o", "--objects",
                      dest="objects",
                      action="store",
                      help="Name of the file containing config objects for this daemon")

    if srBase[len(srBase)-1] != '/':
        srBase = srBase + "/"
    srCodeBase = srBase + "snaproute/src/"

    (opts, args) = parser.parse_args()

    if opts.daemon == None:
        parser.print_usage()
        sys.exit(0)
    else:
        dmnName = opts.daemon

    if opts.module != None:
        modName = opts.module
    else:
        modName = dmnName[:-1]

    if opts.repo != None:
        rName = opts.repo
    else:
        rName = ""

    if opts.objects != None:
        objFile = opts.objects
    else:
        objFile = ""

    createDirectoryStructure(dmnName, modName, rName, objFile)
    writeMainFile()
    writeRpcFile()
    writeRpcHdlFile()
    writeServerFile()
    writeMakeFile()

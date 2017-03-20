import os
import json
import re

OBJECT_MAP_NAME = "gen_objMap.go"
ACTION_MAP_NAME = "gen_actionMap.go"

OBJECTS_NAME = 'objects'
ACTIONS_NAME = 'actions'
srBase = os.environ.get('SR_CODE_BASE', None)
GO_MODEL_BASE_PATH_LIST = [srBase + "/generated/src/models/%s/" % OBJECTS_NAME,
                           srBase + "/snaproute/src/models/objects/"]
JSON_MODEL_REGISTRAION_PATH = srBase + "/snaproute/src/models/objects/"
JSON_ACTION_REGISTRAION_PATH = srBase + "/snaproute/src/models/actions/"
THRIFT_UTILS_PATH = srBase + "/snaproute/src/models/objects/"
THRIFT_UTILS_PATH_ACTIONS = srBase + "/snaproute/src/models/actions/"
CLIENTIF_SRC_PATH = srBase + "/snaproute/src/config/clients/"
#JSON_MODEL_REGISTRAION_PATH = HOME + "/git/reltools/codegentools/gotojson/"
CODE_GENERATION_PATH = srBase + "/reltools/codegentools/gotothrift/"
CLIENTIF_CODE_GENERATION_PATH = srBase + "/generated/src/config/clients/"
CLIENTIF_FILE_PATH = srBase + "/src/config/clients/"
SRC_BASE = srBase + "/snaproute/src/"
OBJMAP_CODE_GENERATION_PATH = srBase + "/snaproute/src/models/%s/" % OBJECTS_NAME
ACTIONMAP_CODE_GENERATION_PATH = srBase + "/snaproute/src/models/%s/" % ACTIONS_NAME
THRIFT_CODE_GENERATION_PATH = srBase + "/generated/src/gorpc/"
DBUTIL_CODE_GENERATION_PATH = THRIFT_CODE_GENERATION_PATH + "dbutils/"
GENERATED_FILES_LIST = srBase + "/reltools/codegentools/._genInfo/generatedGoFiles.txt"

GENERATED_FILES_LISTING_FILE = srBase + '/reltools/codegentools/._genInfo'


goToThirftTypeMap = {
  'bool':          {"native_type": "bool"},
  'uint8':            {"native_type": "byte", "unsigned": True},
  'uint16':           {"native_type": "i16", "unsigned": True},
  'uint32':           {"native_type": "i32", "unsigned": True},
  'uint64':           {"native_type": "i64", "unsigned": True},
  'string':           {"native_type": "string","unsigned": None },
  'float64':          {"native_type": "double", "unsigned": False},
  'int8':             {"native_type": "byte", "unsigned": False},
  'int16':            {"native_type": "i16", "unsigned": False},
  'int32':            {"native_type": "i32", "unsigned": False},
  'int64':            {"native_type": "i64", "unsigned": False},
}

class DaemonObjectsInfo (object) :
    def __init__ (self, name, location, svcName, finalSvcName=None):
        self.name   =  name
        self.location =  location
        self.thriftFileName = SRC_BASE + location + '/'+  name + ".thrift"
        self.thriftUtilsFileName = THRIFT_UTILS_PATH + "gen_" + name + "dbthriftutil.go"
        self.thriftUtilsActionsFileName = THRIFT_UTILS_PATH_ACTIONS + "gen_" + name + "dbthriftutil.go"
        self.clientIfFileName = CLIENTIF_SRC_PATH + "gen_" + name + "clientif.go"
        self.clientLibFileName = CLIENTIF_SRC_PATH + "gen_" + name + "clientLib.go"
        if finalSvcName:
            self.servicesName = finalSvcName
        else: 
            self.servicesName = self.name
        self.SName = svcName
        if "Services" in self.servicesName:
            self.newDeamonName = self.servicesName.rstrip("Services").upper()
        else:
            self.newDeamonName = self.servicesName.upper()
        self.objectDict = {}

    def __str__(self):
        print '%s' %(self.name)
        for name, obj in self.objectDict.iteritems(): 
            print '\t%s  - %s' %(name, obj)
        return ''

    def parseSrcFile(self):
        for objName, info in self.objectDict.iteritems():
            infoFile = srBase+ '/reltools/codegentools/._genInfo/'+objName + 'Members.json'
            with open(infoFile) as fileHdl:
                objMembersData = json.load(fileHdl)
            objMembersStrData = {}
            for attrName, attrInfo in objMembersData.iteritems():
                attrDict = {} 
                for key, val in attrInfo.iteritems() :
                    attrDict[str(key)] = str(val)
                objMembersStrData[str(attrName)] = attrDict

            info['membersInfo'] = objMembersStrData
            

    def addGeneratedFilesNamesToListing (self):
        with open(GENERATED_FILES_LIST, 'a+') as fp:
            fp.write(self.thriftFileName+ '\n')
            fp.write(self.thriftUtilsFileName+ '\n')
            fp.write(self.thriftUtilsActionsFileName+ '\n')
            fp.write(self.clientIfFileName+ '\n')

    def convertMemberInfoToOrderedList(self, structName, structInfo):

        structInfoList = []
        for i in range(len(structInfo['membersInfo'])+1):
            for attrName, attrInfo in structInfo['membersInfo'].iteritems():
                if attrInfo['position'] == "%s" %(i,):
                    yield (attrName, attrInfo)

    def generateThriftInterfaces(self, objectNames):
        thriftfd = open(self.thriftFileName, 'w+')
        thriftfd.write("""//
//Copyright [2016] [SnapRoute Inc]
//
//Licensed under the Apache License, Version 2.0 (the "License");
//you may not use this file except in compliance with the License.
//You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
//	 Unless required by applicable law or agreed to in writing, software
//	 distributed under the License is distributed on an "AS IS" BASIS,
//	 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//	 See the License for the specific language governing permissions and
//	 limitations under the License.
//
//   This is a auto-generated file, please do not edit!
// _______   __       __________   ___      _______.____    __    ____  __  .___________.  ______  __    __  
// |   ____||  |     |   ____\  \ /  /     /       |\   \  /  \  /   / |  | |           | /      ||  |  |  | 
// |  |__   |  |     |  |__   \  V  /     |   (----  \   \/    \/   /  |  |  ---|  |---- |  ,---- |  |__|  | 
// |   __|  |  |     |   __|   >   <       \   \      \            /   |  |     |  |     |  |     |   __   | 
// |  |     |  `----.|  |____ /  .  \  .----)   |      \    /\    /    |  |     |  |     |  `----.|  |  |  | 
// |__|     |_______||_______/__/ \__\ |_______/        \__/  \__/     |__|     |__|      \______||__|  |__| 
//                                                                                                           
		\n""")
        sName = self.SName
        if sName != "nil" :
            thriftfd.write("include \"%s.thrift\"\n" %(sName))
        dmn = self.servicesName
        thriftfd.write("namespace go %s\n" %(dmn))
        thriftfd.write("""typedef i32 int\ntypedef i16 uint16\n""")
        for structName, structInfo in objectNames.objectDict.iteritems ():
            line = 'struct ' + structName + ' {'
            thriftfd.write(line + '\n')
            index = 0

            for attrName, attrInfo in self.convertMemberInfoToOrderedList(structName, structInfo):
                index = index+1
                if attrInfo['isArray'] != 'False' :
                    if str(attrInfo['type']) in goToThirftTypeMap:
                        typeval = goToThirftTypeMap[str(attrInfo['type'])]["native_type"]
                        if str(attrInfo['type']) == 'uint8':
                            typeval = 'byte'
                        nativetype = "list<" + typeval + ">"
                        thriftfd.write("\t%s : %s %s\n" % (index,
                                                           nativetype,
                                                           attrName))
                    else:
                        thriftfd.write("\t%s : %s %s\n" % (index,
                                                           "list<" + str(attrInfo['type']) + ">",
                                                           attrName))
                else:
                    if str(attrInfo['type']) in goToThirftTypeMap:
                        thriftfd.write("\t%s : %s %s\n" % (index,
                                                         goToThirftTypeMap[str(attrInfo['type'])]['native_type'],
                                                         attrName))
                    else:
                        thriftfd.write("\t%s : %s %s\n" % (index,
                                                         str(attrInfo['type']),
                                                         attrName))
            thriftfd.write('}\n')
             
            if 'r' in structInfo['access']:
                thriftfd.write("""struct %sGetInfo {\n\t1: int StartIdx\n\t2: int EndIdx\n\t3: int Count\n\t4: bool More\n\t5: list<%s> %sList\n}\n""" %(structName, structName, structName))


        thriftfd.write("""\nstruct PatchOpInfo {
    1 : string Op
    2 : string Path
    3 : string Value
}
			        \n""")
        if sName == "nil" :
            thriftfd.write("service %sServices {\n" % (dmn.upper()))
        elif "Services" in dmn: 
            thriftfd.write("service %sServices extends %s.%sServices {\n" % (dmn.rstrip("Services").upper(), sName, sName.upper()))
        else :
            thriftfd.write("service %sServices extends %s.%sServices {\n" % (dmn.upper(), sName, sName.upper()))
        for structName, structInfo in objectNames.objectDict.iteritems ():
            s = structName
            if 'w' in structInfo['access'] or 'rw' in structInfo['access']:
                thriftfd.write(
                    """\tbool Create%s(1: %s config);\n\tbool Update%s(1: %s origconfig, 2: %s newconfig, 3: list<bool> attrset, 4: list<PatchOpInfo> op);\n\tbool Delete%s(1: %s config);\n\n""" % (s, s, s, s, s, s, s))

                if structInfo['accelerated']:
                    thriftfd.write(
                        """\toneway void OnewayCreate%s(1: %s config);\n\toneway void OnewayUpdate%s(1: %s origconfig, 2: %s newconfig, 3: list<bool> attrset);\n\toneway void OnewayDelete%s(1: %s config);\n\n""" % (s, s, s, s, s, s, s))
            if 'r' in structInfo['access']: # read only objects Counters/State
                thriftfd.write("""\t%sGetInfo GetBulk%s(1: int fromIndex, 2: int count);\n""" %(s, s))

                keyIndex = 1
                keyList = ""
                for attrName, attrInfo in self.convertMemberInfoToOrderedList(structName, structInfo):
                    if attrInfo['isKey'] != 'False':
                        if str(attrInfo['type']) in goToThirftTypeMap:
                            if keyIndex == 1:
                                keyList = keyList + "%s: " % keyIndex + goToThirftTypeMap[str(attrInfo['type'])]['native_type'] + " " + attrName
                            else:
                                keyList = keyList + ", %s: " % keyIndex + goToThirftTypeMap[str(attrInfo['type'])]['native_type'] + " " + attrName
                        else:
                            if keyIndex == 1:
                                keyList = keyList + "%s: " % keyIndex + str(attrInfo['type']) + " " + attrName
                            else:
                                keyList = keyList + ", %s: " % keyIndex + str(attrInfo['type']) + " " + attrName
                        keyIndex = keyIndex + 1

                thriftfd.write("""\t%s Get%s(%s);\n""" %(s, s, keyList))
            if 'x' in structInfo['access']: # action objects
                thriftfd.write(
                    """\tbool ExecuteAction%s(1: %s config);\n\n""" % (s, s))
        thriftfd.write("}")
        thriftfd.close()
        #print 'Thrift file for %s is %s' %(dmn, self.thriftFileName)
        return 


    def createConvertObjToThriftObj(self, objectNames):
        hasConfigObj = False
        hasActionObj = False
        for structName, structInfo in objectNames.objectDict.iteritems ():
            if structInfo['access'] in ['w', 'rw', 'r', '']:
                hasConfigObj = True
            if structInfo['access'] in ['x']:
                hasActionObj = True

        thriftdbutilfd = open(self.thriftUtilsFileName, 'w+')
        thriftdbutilfd.write("package objects\n")
        if hasConfigObj:
            thriftdbutilfd.write("""import (\n 
                                   "%s"\n)""" %(self.servicesName))
            
        thriftdbutilactionfd = open(self.thriftUtilsActionsFileName, 'w+')
        thriftdbutilactionfd.write("package actions\n")
        if hasActionObj:
            thriftdbutilactionfd.write("""import (\n 
                                         "%s"\n)""" %(self.servicesName))

        for structName, structInfo in objectNames.objectDict.iteritems ():
            structName = str(structName)
            s = structName
            d = self.name
            if structInfo['access'] in ['w', 'rw', 'r', '']:
                fd = thriftdbutilfd
            if structInfo['access'] in ['x']:
                fd = thriftdbutilactionfd
            if fd is not None:
                fd.write("""\nfunc Convert%s%sObjToThrift(dbobj *%s, thriftobj *%s.%s) { """ %(d, s, s, self.servicesName, s))
                for i, (k, v) in enumerate(structInfo['membersInfo'].iteritems()):
                    attrType = v['type'][1:] if v['type'].startswith('u') else v['type']

                    if v['isArray'] != 'False':
                        if attrType in goToThirftTypeMap:
                            fd.write("""\nfor _, data%s := range dbobj.%s {
                                                        thriftobj.%s = append(thriftobj.%s, %s(data%s))
                                                    }\n""" %(i, k, k, k, attrType, i))
                        else:
                            fd.write("""\nfor _, data%s := range dbobj.%s {
                                                        thriftdata%s := new(%s.%s)
                                                        Convert%s%sObjToThrift(&data%s, thriftdata%s)
                                                        thriftobj.%s = append(thriftobj.%s, thriftdata%s)
                                                    }\n""" %(i, k, i, self.servicesName, attrType, d, attrType, i, i, k, k, i))
                    else:
                        if attrType in goToThirftTypeMap:
                            fd.write("""thriftobj.%s = %s(dbobj.%s)\n""" % (k, attrType, k)) 
                        else:
                            fd.write("""thriftobj.%s = new(%s.%s)\n""" % (k, self.servicesName, attrType))
                            fd.write("""Convert%s%sObjToThrift(&dbobj.%s, thriftobj.%s)\n""" % (d, attrType, k, k))
                fd.write("""}\n""")


                fd.write("""\nfunc ConvertThriftTo%s%sObj(thriftobj *%s.%s, dbobj *%s) { """ %(d, s, self.servicesName, s, s))

                for i, (k, v) in enumerate(structInfo['membersInfo'].iteritems()):
                    attrInfo = v
                    #attrType = v['type'][1:] if v['type'].startswith('u') else v['type']
                    attrType = attrInfo['type']
                    if attrInfo['isArray'] != 'False':
                        if attrType in goToThirftTypeMap:
                            fd.write("""\nfor _, data%s := range thriftobj.%s {
                                                    dbobj.%s = append(dbobj.%s, %s(data%s))
                                                }\n""" %(i, k, k, k, attrType, i))
                        else:
                            fd.write("""\nfor _, thriftdata%s := range thriftobj.%s {
                                                        dbobjdata%s := new(%s)
                                                        ConvertThriftTo%s%sObj(thriftdata%s, dbobjdata%s)
                                                        dbobj.%s = append(dbobj.%s, *dbobjdata%s)
                                                    }\n""" %(i, k, i, attrType, d, attrType, i, i, k, k, i))
                    else:
                        if attrType in goToThirftTypeMap:
                            fd.write("""dbobj.%s = %s(thriftobj.%s)\n""" % (k, attrType, k))
                        else:
                            fd.write("""ConvertThriftTo%s%sObj(thriftobj.%s, &dbobj.%s)\n""" % (d, attrType, k, k)) 

                fd.write("""}\n""")
        thriftdbutilfd.close()
        thriftdbutilactionfd.close()
   
    def clientIfBasicHelper(self, clientIfFd):
        clientIfFd.write("""type %sClient struct {
                                    ipcutils.IPCClientBase
                                    ClientHdl *%s.%sServicesClient
                                }\n""" % (self.newDeamonName, self.servicesName, self.newDeamonName))
        clientIfFd.write("""
                            func (clnt *%sClient) Initialize(name string, address string) {
                                clnt.Name = name
                                clnt.Address = address
                                clnt.Enabled = true
                                clnt.ApiHandlerMutex = sync.RWMutex{}
                                return
                            }\n""" % (self.newDeamonName,))
        clientIfFd.write("""
                            func (clnt *%sClient) ConnectToServer() bool {
                                clnt.TTransport, clnt.PtrProtocolFactory, _ = ipcutils.CreateIPCHandles(clnt.Address)
                                if clnt.TTransport != nil && clnt.PtrProtocolFactory != nil {
                                    clnt.ClientHdl = %s.New%sServicesClientFactory(clnt.TTransport, clnt.PtrProtocolFactory)
                                    if clnt.ClientHdl != nil {
                                        clnt.IsConnected = true
                                    } else {
                                        clnt.IsConnected = false
                                    }
                                }
                                return true
                            }\n""" % (self.newDeamonName, self.servicesName, self.newDeamonName))
        clientIfFd.write("""
                            func (clnt *%sClient) DisconnectFromServer() bool {
                                 var err error
                                 if clnt.IsConnectedToServer() {
                                     err = clnt.CloseIPCHandles()
                                     if err != nil {
                                         fmt.Println("Failed to close IPC handles: ", err)
                                         return false
                                     }
                                     clnt.IsConnected = false
                                     clnt.ClientHdl = nil
                                 }
                                 return true
                            }\n""" % (self.newDeamonName))
        clientIfFd.write("""
                            func (clnt *%sClient) IsConnectedToServer() bool {
                                return clnt.IsConnected
                            }\n""" % (self.newDeamonName,))
        clientIfFd.write("""
                            func (clnt *%sClient) DisableServer() bool {
                                clnt.Enabled = false
                                return true
                            }\n""" % (self.newDeamonName,))
        clientIfFd.write("""
                            func (clnt *%sClient) IsServerEnabled() bool {
                                return clnt.Enabled
                            }\n""" % (self.newDeamonName,))
        clientIfFd.write("""
                            func (clnt *%sClient) GetServerName() string {
                                return clnt.Name
                            }\n""" % (self.newDeamonName,))
        clientIfFd.write("""
                            func (clnt *%sClient) LockApiHandler() {
                                clnt.ApiHandlerMutex.Lock()
                            }\n""" % (self.newDeamonName,))
        clientIfFd.write("""
                            func (clnt *%sClient) UnlockApiHandler() {
                                clnt.ApiHandlerMutex.Unlock()
                            }\n""" % (self.newDeamonName,))

    def createClientIfCheckIfRouteExistFuncs(self,clientIfFd,objectNames) :
	    clientIfFd.write("""
func CheckIfV6RouteKeyExists(thriftobj *ribd.IPv6Route, dbHdl *dbutils.DBUtil) (*ribd.IPv6Route, bool, error) {
	cfg := &ribd.IPv6Route{}
	cfg = thriftobj
	isCidr := strings.Contains(cfg.DestinationNw, "/")
	if isCidr {
		/*
		   the given address is in CIDR format
		*/
		ip, ipNet, err := net.ParseCIDR(cfg.DestinationNw)
		if err != nil {
			return cfg, false, errors.New(fmt.Sprintln("Invalid Desitnation IP address", cfg.DestinationNw))
		}
		_, err = netutils.GetNetworkPrefixFromCIDR(cfg.DestinationNw)
		if err != nil {
			return cfg, false, errors.New(fmt.Sprintln("RouteConfigValidationCheck for route:", cfg, " Invalid destination ip/network Mask"))
		}
		/*
		   Convert the CIDR format address to IP and mask strings
		*/
		cfg.DestinationNw = ip.String()
		ipMask := make(net.IP, 16)
		copy(ipMask, ipNet.Mask)
		ipMaskStr := net.IP(ipMask).String()
		cfg.NetworkMask = ipMaskStr
		/*
			In case where user provides CIDR address, we need to check if there is a duplicate route with destinationNw/networkMask format
		*/
		if dbHdl != nil {
			key := "IPv6Route#" + cfg.DestinationNw + "#" + cfg.NetworkMask
			var dbObjCfg objects.IPv6Route
			dbObjCfg.DestinationNw = cfg.DestinationNw
			dbObjCfg.NetworkMask = cfg.NetworkMask
			_, err := dbHdl.GetObjectFromDb(dbObjCfg, key)
			if err == nil {
				return cfg, true, errors.New(fmt.Sprintln("Duplicate Entry with key:", key))
			}
		}
	} else {
		cidrAddr,err := netutils.GetCIDR(cfg.DestinationNw,cfg.NetworkMask)
		if err != nil {
			return cfg, false, errors.New(fmt.Sprintln("Invalid Desitnation IP address", cfg.DestinationNw))
		}
		if dbHdl != nil {
			key := "IPv6Route#" + cidrAddr+"#"
			var dbObjCfg objects.IPv6Route
			dbObjCfg.DestinationNw = cidrAddr
			_, err := dbHdl.GetObjectFromDb(dbObjCfg, key)
			if err == nil {
				return cfg, true, errors.New(fmt.Sprintln("Duplicate Entry with key:", key))
			}
		}
	}
	return cfg, false, nil
}
func CheckIfV4RouteKeyExists(thriftobj *ribd.IPv4Route, dbHdl *dbutils.DBUtil) (*ribd.IPv4Route, bool, error) {
	cfg := &ribd.IPv4Route{}
	cfg = thriftobj
	isCidr := strings.Contains(cfg.DestinationNw, "/")
	if isCidr {
		/*
		   the given address is in CIDR format
		*/
		ip, ipNet, err := net.ParseCIDR(cfg.DestinationNw)
		if err != nil {
			return cfg, false, errors.New(fmt.Sprintln("Invalid Desitnation IP address", cfg.DestinationNw))
		}
		_, err = netutils.GetNetworkPrefixFromCIDR(cfg.DestinationNw)
		if err != nil {
			return cfg, false, errors.New(fmt.Sprintln("RouteConfigValidationCheck for route:", cfg, " Invalid destination ip/network Mask"))
		}
		/*
		   Convert the CIDR format address to IP and mask strings
		*/
		cfg.DestinationNw = ip.String()
		ipMask := make(net.IP, 4)
		copy(ipMask, ipNet.Mask)
		ipMaskStr := net.IP(ipMask).String()
		cfg.NetworkMask = ipMaskStr
		/*
			In case where user provides CIDR address, we need to check if there is a duplicate route with destinationNw/networkMask format
		*/
		if dbHdl != nil {
			var dbObjCfg objects.IPv4Route
			dbObjCfg.DestinationNw = cfg.DestinationNw
			dbObjCfg.NetworkMask = cfg.NetworkMask
			key := "IPv4Route#" + cfg.DestinationNw + "#" + cfg.NetworkMask
			_, err := dbHdl.GetObjectFromDb(dbObjCfg, key)
			if err == nil {
				return cfg, true, errors.New(fmt.Sprintln("Duplicate Entry with key:", key))
			}
		}
	} else {
		cidrAddr,err := netutils.GetCIDR(cfg.DestinationNw,cfg.NetworkMask)
		if err != nil {
			return cfg, false, errors.New(fmt.Sprintln("Invalid Desitnation IP address", cfg.DestinationNw))
		}
		if dbHdl != nil {
			key := "IPv4Route#" + cidrAddr+"#"
			var dbObjCfg objects.IPv4Route
			dbObjCfg.DestinationNw = cidrAddr
			_, err := dbHdl.GetObjectFromDb(dbObjCfg, key)
			if err == nil {
				return cfg, true, errors.New(fmt.Sprintln("Duplicate Entry with key:", key))
			}
		}
	}
	return cfg, false, nil
}
		""")

    def createClientIfCreateObject(self, clientIfFd, objectNames):
        clientIfFd.write("""
                            func (clnt *%sClient) CreateObject(obj objects.ConfigObj, dbHdl *dbutils.DBUtil) (error, bool) {
                            var err error
                            var ok bool
                            ok = true
                            defer clnt.UnlockApiHandler()
                            clnt.LockApiHandler()
                                switch obj.(type) {\n""" % (self.newDeamonName,))
        for structName, structInfo in objectNames.objectDict.iteritems ():
            structName = str(structName)
            s = structName
            d = self.name
            if structInfo['access'] in ['w', 'rw']:
                clientIfFd.write("""
                                    case objects.%s :
                                    data := obj.(objects.%s)
                                    conf := %s.New%s()\n""" % (s, s, self.servicesName, s))
                clientIfFd.write("""objects.Convert%s%sObjToThrift(&data, conf)""" %(d, s))
                if s == "IPv6Route":
                    clientIfFd.write(""" 
							cfg, exist, err := CheckIfV6RouteKeyExists(conf, dbHdl)
       		                 if err != nil {
			                     return err, false
		                     }
		                     if exist {
			                     return err, false
		                     }
		                     ok, err = clnt.ClientHdl.CreateIPv6Route(cfg)
					""")
                elif s == "IPv4Route":
                    clientIfFd.write(""" 
							cfg, exist, err := CheckIfV4RouteKeyExists(conf, dbHdl)
       		                 if err != nil {
			                     return err, false
		                     }
		                     if exist {
			                     return err, false
		                     }
		                     ok, err = clnt.ClientHdl.CreateIPv4Route(cfg)
                      """)
                else :
                    clientIfFd.write("""
                                    ok, err = clnt.ClientHdl.Create%s(conf)
                                    """ % (s))
                clientIfFd.write("""
                                    if err == nil && ok == true {
                                        err = dbHdl.StoreObjectInDb(data)
                                        if err != nil {
				            fmt.Println("Store object in DB failed:", err)
                                            return err, false
                                        }
                                    } else {
				        fmt.Println("Create failed:", err)
                                        return err, false
                                    }
                                    break\n""")
        clientIfFd.write("""default:
                                    break
                                }

                                return err, ok
                            }\n""")

    def createClientIfDeleteObject(self, clientIfFd, objectNames):
        clientIfFd.write("""
                            func (clnt *%sClient) DeleteObject(obj objects.ConfigObj, objKey string, dbHdl *dbutils.DBUtil) (error, bool) {
                                var err error
                                var ok bool
                                ok = true
                                defer clnt.UnlockApiHandler()
                                clnt.LockApiHandler()
                                switch obj.(type) {\n""" % (self.newDeamonName,))
        for structName, structInfo in objectNames.objectDict.iteritems ():
            structName = str(structName)
            s = structName
            d = self.name
            if structInfo['access'] in ['w', 'rw']:
                clientIfFd.write("""
                                    case objects.%s :
                                    data := obj.(objects.%s)
                                    conf := %s.New%s()\n""" % (s, s, self.servicesName, s))
                clientIfFd.write("""objects.Convert%s%sObjToThrift(&data, conf)""" %(d, s))
                clientIfFd.write("""
                                    ok, err = clnt.ClientHdl.Delete%s(conf)
                                    """% (s))
                clientIfFd.write("""
                                    if err == nil && ok == true {
                                        err = dbHdl.DeleteObjectFromDb(data)
                                        if err != nil {
				            fmt.Println("Delete object from DB failed:", err)
                                            return err, false
                                        }
                                    } else {
				        fmt.Println("Delete failed:", err)
                                        return err, false
                                    }
                                    break\n""")
        clientIfFd.write("""default:
                                    break
                                }

                                return err, ok
                            }\n""")

    def createClientIfGetObject(self, clientIfFd, objectNames):
        clientIfFd.write("""
                            func (clnt *%sClient) GetObject(obj objects.ConfigObj, dbHdl *dbutils.DBUtil) (error, objects.ConfigObj) {
            defer clnt.UnlockApiHandler()
            clnt.LockApiHandler()
            switch obj.(type) {\n""" % (self.newDeamonName))
        for structName, structInfo in objectNames.objectDict.iteritems ():
            structName = str(structName)
            s = structName
            d = self.name
            if 'r' in structInfo['access'] and 'usesStateDB' in structInfo and not(structInfo['usesStateDB']):
                clientIfFd.write("""
                                    case objects.%s :
                                    data := obj.(objects.%s)
                                    conf := %s.New%s()\n""" % (s, s, self.servicesName, s))
                clientIfFd.write("""objects.Convert%s%sObjToThrift(&data, conf)\n""" %(d, s))
                keyIndex = 1
                keyList = ""
                for attrName, attrInfo in self.convertMemberInfoToOrderedList(structName, structInfo):
                    if attrInfo['isKey'] != 'False':
                        if keyIndex == 1:
                            keyList = keyList + "conf." + attrName
                        else:
                            keyList = keyList + ", " + "conf." + attrName
                        keyIndex = keyIndex + 1

                clientIfFd.write("""stateObj := new(objects.%s)\n""" %(s))
                clientIfFd.write("""
                    if clnt.ClientHdl != nil {
                        retObj, err := clnt.ClientHdl.Get%s(%s)
                        if err == nil {\n""" %(s, keyList))
                clientIfFd.write("""objects.ConvertThriftTo%s%sObj(retObj, stateObj)\n""" % (d, s))
                clientIfFd.write("""
                            return err, stateObj
                        } else {
                            return err, nil
                        }
                    }
                    break\n""")
            elif 'usesStateDB' in structInfo and structInfo['usesStateDB']:
                clientIfFd.write("""\ncase objects.%s :\n""" % (s,))
                clientIfFd.write("""
                        retObj, err := dbHdl.GetObjectFromDb(obj, obj.GetKey())
                        if err != nil {
                            return err, nil
                        } else {
                            return nil, retObj
                        }
                        break""")

        clientIfFd.write("""\ndefault:
                                    break
                                }
                        return nil, nil
                            }\n""")

    def createClientIfExecuteAction(self, clientIfFd, objectNames):
        clientIfFd.write("""
                            func (clnt *%sClient) ExecuteAction(obj actions.ActionObj) error {
            defer clnt.UnlockApiHandler()
            clnt.LockApiHandler()
            switch obj.(type) {\n""" % (self.newDeamonName))
        for structName, structInfo in objectNames.objectDict.iteritems ():
            structName = str(structName)
            s = structName
            d = self.name
            if 'x' in structInfo['access']:
                clientIfFd.write("""
                                    case actions.%s :
                                    data := obj.(actions.%s)
                                    conf := %s.New%s()\n""" % (s, s, self.servicesName, s))
                clientIfFd.write("""actions.Convert%s%sObjToThrift(&data, conf)""" %(d, s))
                clientIfFd.write("""
                    if clnt.ClientHdl != nil {
                        _, err := clnt.ClientHdl.ExecuteAction%s(conf)
                        return err\n""" %(s))
                clientIfFd.write("""
                    }
                    break\n""")
        clientIfFd.write("""\ndefault:
                                    break
                                }
                        return nil
                            }\n""")

    def createClientIfUpdateObject(self, clientIfFd, objectNames):
        clientIfFd.write("""
                            func (clnt *%sClient) UpdateObject(dbObj objects.ConfigObj, obj objects.ConfigObj, attrSet []bool, patchOpInfo []objects.PatchOpInfo, objKey string, dbHdl *dbutils.DBUtil) (error, bool) {
            var ok bool
            var err error
	    ok = true
            err = nil
            defer clnt.UnlockApiHandler()
            clnt.LockApiHandler()
			
			var op []*%s.PatchOpInfo = make([]*%s.PatchOpInfo, 0)
			var opArr []%s.PatchOpInfo = make([]%s.PatchOpInfo,0)
	        for _, tempOp := range patchOpInfo {
		        opArr = append(opArr, %s.PatchOpInfo{tempOp.Op, tempOp.Path, tempOp.Value})
	        }
	        for opIdx := 0; opIdx < len(opArr); opIdx++ {
	 	        op = append(op, &opArr[opIdx])
 	        }
            switch obj.(type) {
        """ %(self.newDeamonName,self.servicesName,self.servicesName,self.servicesName, self.servicesName, self.servicesName))
        for structName, structInfo in objectNames.objectDict.iteritems ():
            structName = str(structName)
            s = structName
            d = self.name
            array_obj = 'False'
            for attrName, attrInfo in self.convertMemberInfoToOrderedList(structName, structInfo):
                if attrInfo['isArray'] != 'False' :
                    array_obj = 'True'				
            if structInfo['access'] in ['w', 'rw']:
                clientIfFd.write("""\ncase objects.%s :""" % (s,))
                clientIfFd.write("""\n// cast original object
                origdata := dbObj.(objects.%s)
                updatedata := obj.(objects.%s)\n""" %(s, s) )
                clientIfFd.write("""// create new thrift objects
                origconf := %s.New%s()\nupdateconf := %s.New%s()\n""" %(self.servicesName, s, self.servicesName, s))
                clientIfFd.write("""objects.Convert%s%sObjToThrift(&origdata, origconf)
                objects.Convert%s%sObjToThrift(&updatedata, updateconf)""" %(d, s, d, s))
                clientIfFd.write("""
                    if clnt.ClientHdl != nil {
                        ok, err = clnt.ClientHdl.Update%s(origconf, updateconf, attrSet, op)
                        if err == nil && ok == true {\n""" %s)
                clientIfFd.write(""" 
                              err = dbHdl.UpdateObjectInDb(updatedata, dbObj, attrSet)
                              if err != nil {
			                     fmt.Println("Update object in DB failed:", err)
                                  return err, false
                              } 
						} else {
                                  return err, false
                          }
					}
                    break\n""" )

        clientIfFd.write("""\ndefault:
                                    break
                                }
                    return err, ok

                }\n""")

    def createClientIfGetBulkObject(self, clientIfFd, objectNames):
        clientIfFd.write("""
                            func (clnt *%sClient) GetBulkObject(obj objects.ConfigObj, dbHdl *dbutils.DBUtil, currMarker int64, count int64) (err error,
                                            objCount int64,
                                            nextMarker int64,
                                            more bool,
                                            objs []objects.ConfigObj) {
            defer clnt.UnlockApiHandler()
            clnt.LockApiHandler()
            switch obj.(type) {
        \n""" %(self.newDeamonName))
        for structName, structInfo in objectNames.objectDict.iteritems ():
            structName = str(structName)
            s = structName
            d = self.name
            if 'r' in structInfo['access'] and 'usesStateDB' in structInfo and not (structInfo['usesStateDB']):
                clientIfFd.write("""\ncase objects.%s :\n""" % (s,))

                clientIfFd.write("""
                    if clnt.ClientHdl != nil {
                        bulkInfo, _ := clnt.ClientHdl.GetBulk%s(%s.Int(currMarker), %s.Int(count))
                        if bulkInfo != nil &&bulkInfo.Count != 0 {
                            objCount = int64(bulkInfo.Count)
                            more = bool(bulkInfo.More)
                            nextMarker = int64(bulkInfo.EndIdx)
                            for i := 0; i < int(bulkInfo.Count); i++ {
                                ret_obj := new(objects.%s)
                                if len(objs) == 0 {
                                    objs = make([]objects.ConfigObj, 0)
                                }\n""" %(s, self.servicesName, self.servicesName, s))

                clientIfFd.write("""\nobjects.ConvertThriftTo%s%sObj(bulkInfo.%sList[i], ret_obj)""" % (d, s, s))
                clientIfFd.write("""\nobjs = append(objs, ret_obj)
                                        }
                            } else {
                            }
                    }
                    break\n""")
            elif 'usesStateDB' in structInfo and structInfo['usesStateDB']:
                clientIfFd.write("""\ncase objects.%s :\n""" % (s,))
                clientIfFd.write("""
                        err, objCount, nextMarker, more, objs = dbHdl.GetBulkObjFromDb(obj, currMarker, count)
                        if err != nil {
                            return nil, objCount, nextMarker, more, objs
                        }
                        break""")

        clientIfFd.write("""\ndefault:
                                    break
                                }
                    return nil, objCount, nextMarker, more, objs
                }\n""")

    def generateClientIf(self, objectNames):
        array_obj = 'False'
        for structName, structInfo in objectNames.objectDict.iteritems ():
            structName = str(structName)
            for attrName, attrInfo in self.convertMemberInfoToOrderedList(structName, structInfo):
                if attrInfo['isArray'] != 'False' :
                    if 'w' in structInfo['access'] :
                        array_obj = 'True'				
        clientIfFd = open(self.clientIfFileName, 'w+')
        clientIfFd.write("""
//Copyright [2016] [SnapRoute Inc]
//
//Licensed under the Apache License, Version 2.0 (the "License");
//you may not use this file except in compliance with the License.
//You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
//	 Unless required by applicable law or agreed to in writing, software
//	 distributed under the License is distributed on an "AS IS" BASIS,
//	 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//	 See the License for the specific language governing permissions and
//	 limitations under the License.
//
//   This is a auto-generated file, please do not edit!
// _______   __       __________   ___      _______.____    __    ____  __  .___________.  ______  __    __  
// |   ____||  |     |   ____\  \ /  /     /       |\   \  /  \  /   / |  | |           | /      ||  |  |  | 
// |  |__   |  |     |  |__   \  V  /     |   (----  \   \/    \/   /  |  |  ---|  |---- |  ,---- |  |__|  | 
// |   __|  |  |     |   __|   >   <       \   \      \            /   |  |     |  |     |  |     |   __   | 
// |  |     |  `----.|  |____ /  .  \  .----)   |      \    /\    /    |  |     |  |     |  `----.|  |  |  | 
// |__|     |_______||_______/__/ \__\ |_______/        \__/  \__/     |__|     |__|      \______||__|  |__| 
//                                                                                                           
		\n""")
        clientIfFd.write("package clients\n")
        #if (len([ x for x,y in accessDict.iteritems() if x in crudStructsList and 'r' in y]) > 0):
        # BELOW CODE WILL BE FORMATED BY GOFMT
        clientIfFd.write("""import (\n "%s"\n"fmt"\n"models/objects"\n"models/actions"\n"sync"\n"utils/ipcutils"\n"utils/dbutils"\n""" % self.servicesName)
        if "ribd" in self.clientIfFileName :
		    clientIfFd.write(""" "errors" \n"strings" \n"net" \nnetutils "utils/netUtils" \n""")
        #if array_obj == 'True' :
            #clientIfFd.write(""" "reflect"\n""" )		
        clientIfFd.write(""")\n""")
        clientIfFd.write("""//Dummy import\n""")
        clientIfFd.write("""var _ actions.ActionObj\n""")
        self.clientIfBasicHelper(clientIfFd)
        if "ribd" in self.clientIfFileName :
		    print 'ribd client:generate checkifv4/v6 exists routines'
		    self.createClientIfCheckIfRouteExistFuncs(clientIfFd,objectNames)
        self.createClientIfCreateObject(clientIfFd, objectNames)
        self.createClientIfDeleteObject(clientIfFd, objectNames)
        self.createClientIfUpdateObject(clientIfFd, objectNames)
        self.createClientIfGetBulkObject(clientIfFd, objectNames)
        self.createClientIfGetObject(clientIfFd, objectNames)
        self.createClientIfExecuteAction(clientIfFd, objectNames)
        
        clientIfFd.close()

    def generateClientLib(self):
        clientLibFd = open(self.clientLibFileName, 'w+')
        clientLibFd.write("package %sLib\n" %(self.name))
        clientLibFd.write("""import (\n "utils/logging" \n) \n""")
        structLines = []
        methodLines = []
        for objName, objInfo in self.objectDict.iteritems() :
            #print '## %s Object name  %s' %(objName, objInfo)
            attrInfo = objInfo['membersInfo']
            attrList  = [None]*len(attrInfo)
            for attrName, info in attrInfo.iteritems():
                info['name'] = attrName
                attrList[int(info['position']) -1] = info
            structLines.append('type %s  struct  {\n' %(objName))
            
            createMethod = 'create'+objName + ' ( '
            deleteMethod = 'delete'+objName + ' ( '
            updateMethod = 'update'+objName + ' ( '
            getBulkMethod = 'GetBulk'+objName + ' ( currMark, count int ) ( *' + objName+'GetInfo, error)\n'
            createArgs = ''
            deleteArgs = ''
            updateArgs = ''
            for attr in attrList:
                structLines.append('%s   %s\n' %( attr['name'], attr['type']))
                if createArgs == '':
                    createArgs = createArgs +  attr['name'] + ' ' + attr['type']
                else:
                    createArgs = createArgs + ',' +  attr['name'] + ' ' + attr['type']
                if attr['isKey'] == 'True': 
                    if deleteArgs == '':
                        deleteArgs = deleteArgs +  attr['name'] + ' ' + attr['type']
                    else:
                        deleteArgs = deleteArgs + ',' +  attr['name'] + ' ' + attr['type']
            methodLines.append (createMethod + createArgs + ' ) (rv int32,  err error)\n')
            methodLines.append (updateMethod + createArgs + ' ) (rv int32,  err error)\n')
            methodLines.append (deleteMethod + deleteArgs + ' ) (rv int32,  err error)\n')
            methodLines.append (getBulkMethod)
            structLines.append('}\n')
        constructorLines = []
        constructorLines.append('func New%sClientInit (plugin string, paramsFile string, logger *logging.Writer) %sCleintIntf{\n' %(self.name, self.name))
        constructorLines.append('if plugin == "Flexswitch" {\n')
        constructorLines.append('clientHdl := get%sThriftClientHdl(paramsFile, logger)\n' %(self.name))
        constructorLines.append('if clientHdl == nil {\n' +
                                 'logger.Err("Unable Initialize %s Client")\n' %(self.name) +
                                 'return nil\n'+
                                 '}\n'+
                                 'return &FS%sClientMgr{clientHdl}\n' %(self.name)+
                                 '} else if plugin == "OvsDB" {\n'+
                                 'return &OvsDBAsicdClientMgr{100}\n' + 
                                 '}\n'+
                                 'return nil\n' + 
                                 '} \n')
        clientLibFd.writelines(structLines)
        clientLibFd.write('type ' +self.servicesName + 'Intf' + ' interface  {\n')
        clientLibFd.writelines(methodLines)
        clientLibFd.write(' }\n')
        clientLibFd.writelines(constructorLines)
        clientLibFd.close()

gDryRun =  False
def generateThriftAndClientIfs():
    # generate thrift code from go code
    genObjInfoJson = JSON_MODEL_REGISTRAION_PATH + 'genObjectConfig.json'
    genActionInfoJson = JSON_ACTION_REGISTRAION_PATH + 'genObjectAction.json'
    goDmnDirsInfoJson = JSON_MODEL_REGISTRAION_PATH + 'goObjInfo.json'
    yangDmnDirsInfoJson = JSON_MODEL_REGISTRAION_PATH + 'yangObjInfo.json'
    goActionDmnDirsInfoJson = JSON_ACTION_REGISTRAION_PATH + 'goActionInfo.json'

    ownerDirsInfo = {} 
    ownerInternalServiceInfo = {}
    ownerFinalServiceInfo = {}
    for dirFile  in [goDmnDirsInfoJson, yangDmnDirsInfoJson, goActionDmnDirsInfoJson]:
        with open(dirFile) as locnFile:
            objData = json.load(locnFile)

        for dmn, info in objData.iteritems():
            if not ownerDirsInfo.has_key(info['owner']):
                ownerDirsInfo[info['owner']] = info['location']
                ownerInternalServiceInfo[info['owner']] = info['svcName']
                if info.has_key('finalSvcName'):
                    ownerFinalServiceInfo[info['owner']] = info['finalSvcName']

    
    for infoFileJson  in [genObjInfoJson]:
        with open(infoFileJson) as infoFile:
            objData = json.load(infoFile)
    
    for infoFileJson  in [genActionInfoJson]:
        with open(infoFileJson) as infoFile:
            actionData = json.load(infoFile)

    objData.update(actionData)

    ownerToObjMap = {}
    for name,  dtls in objData.iteritems():
        finalSvcName =None 
        if ownerFinalServiceInfo.has_key(dtls['owner']):
            finalSvcName = ownerFinalServiceInfo[dtls['owner']]

        if ownerToObjMap.has_key(dtls['owner']):
            dmnObj = ownerToObjMap[dtls['owner']]
        else :
            dmnObj = DaemonObjectsInfo (dtls['owner'], ownerDirsInfo[dtls['owner']], ownerInternalServiceInfo[dtls['owner']], finalSvcName)
            ownerToObjMap[dtls['owner']] = dmnObj
        dmnObj.objectDict[name] = dtls

    for dmn, entry in ownerToObjMap.iteritems():
        if dmn == 'local':
            continue
        entry.parseSrcFile()
        entry.generateThriftInterfaces(ownerToObjMap[dmn])
        entry.createConvertObjToThriftObj(ownerToObjMap[dmn])
        entry.generateClientIf(ownerToObjMap[dmn]) 
        entry.addGeneratedFilesNamesToListing ()
        #if dmn == 'asicd': 
        #    entry.generateClientLib ()
    return


def generateConfigObjectMap():
    genObjInfoJson = JSON_MODEL_REGISTRAION_PATH + 'genObjectConfig.json'
    fd = open(OBJMAP_CODE_GENERATION_PATH + OBJECT_MAP_NAME, 'w+')
    fd.write("""package %s\n\n""" % OBJECTS_NAME)
    fd.write("""var GenConfigObjectMap = map[string] ConfigObj{\n""")

    with open(genObjInfoJson) as infoFile:
        objData = json.load(infoFile)

    for name,  dtls in objData.iteritems():
        if "w" in dtls['access'] or "r" in dtls['access']:
            line  = "\"%s\" :    &%s{}," %(name.lower(), name)
            fd.write(line+"\n")

    fd.write("""}\n""")
    fd.close()
    with open(GENERATED_FILES_LIST, 'a+') as fp:
        fp.write(OBJMAP_CODE_GENERATION_PATH + OBJECT_MAP_NAME+ '\n')


def generateActionObjectMap():
    genActionInfoJson = JSON_ACTION_REGISTRAION_PATH + 'genObjectAction.json'
    fd = open(ACTIONMAP_CODE_GENERATION_PATH + ACTION_MAP_NAME, 'w+')
    fd.write("""package %s\n\n""" % ACTIONS_NAME)
    fd.write("""var GenActionObjectMap = map[string] ActionObj{\n""")

    with open(genActionInfoJson) as infoFile:
        actionData = json.load(infoFile)

    for name,  dtls in actionData.iteritems():
        if "x" in dtls['access']:
            line  = "\"%s\" :    &%s{}," %(name.lower(), name)
            fd.write(line+"\n")

    fd.write("""}\n""")
    fd.close()
    with open(GENERATED_FILES_LIST, 'a+') as fp:
        fp.write(ACTIONMAP_CODE_GENERATION_PATH + ACTION_MAP_NAME+ '\n')

    

if __name__ == "__main__":
    generateConfigObjectMap ()
    generateActionObjectMap ()
    generateThriftAndClientIfs()

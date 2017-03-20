import json
import operator
def isNumericAttr (attrInfo) :
    if attrInfo['isArray'] == 'False':
        return attrInfo['type'] in ["int32", "uint32", "uint8", "uint16", "int16"]
    else:
        return False

def isListAttr(attrInfo) :
    return attrInfo['isArray'] == 'True'

def isBoolean(attrType) :
    return attrType in ["bool"]

def boolFromString (val) :
    if val == 'false':
        return False
    else:
        return True 

class FlexObject(object) :
    TAB = "    " 
    def __init__ (self,     # Yours truly
                  name,     # Object Name 
                  access,   # Access r/w
                  multiplicity, # UML notation *=many 1=1
                  canCreate, # this object can be created or not
                  attrFile): # Location of the attributes description
        self.name = str(name)
        self.access = access
        self.attrFile = attrFile
        self.multiplicity = multiplicity
        self.canCreate = canCreate
        self.attrDict = {}
        self.attrList = None
        
        with open(attrFile) as fileHdl:
            attrDict = json.load(fileHdl)
            attrList = [None] *len(attrDict)
            keysList = []
            dfltAttrList = []
            for attrName, tmpInfo in attrDict.iteritems():
                tmpDict = {}
                for k,v in tmpInfo.iteritems():
                    tmpDict[str(k)] = str(v)

                self.attrDict[str(attrName)] = tmpDict
                if tmpDict['isKey'] == 'True':
                    keysList.append((attrName, self.attrDict[str(attrName)]))
                elif tmpDict['default'] != '':
                    dfltAttrList.append((attrName, self.attrDict[str(attrName)]))
                else:
                    attrList[tmpInfo['position'] -1] = (attrName, self.attrDict[str(attrName)])

            self.attrList =  keysList + [x for x in attrList if x!= None] + dfltAttrList 

                
    def createGetByIdMethod (self, fileHdl, urlPath):
        tabs = self.TAB
        #lines = [ "\n"+ tabs + "@processReturnCode"]
        lines = []
        lines.append("\n"+ tabs + "def get" + self.name + "ById(self, objectId ):\n")
        tabs = tabs + self.TAB
        if self.name.endswith('State'):
            objName = self.name[:-5]
        else:
            objName = self.name
        lines.append (tabs + "reqUrl =  " + urlPath + " + " + "\'%s\'" %(objName))
        lines[-1] = lines[-1] + "+\"/%s\"%(objectId)\n"
        lines.append(tabs + "if self.authenticate == True:\n")
        lines.append(tabs + tabs + "r = requests.get(reqUrl, data=None, headers=headers, timeout=self.timeout, auth=(self.user, self.passwd), verify=False) \n")
        lines.append(tabs + "else:\n")
        lines.append(tabs + tabs + "r = requests.get(reqUrl, data=None, headers=headers, timeout=self.timeout) \n")
        lines.append(tabs + "return r\n")
        fileHdl.writelines(lines)

    def createGetMethod (self, fileHdl, urlPath):
        tabs = self.TAB
        #lines = [ "\n"+ tabs + "@processReturnCode"]
        lines = []
        lines.append("\n"+ tabs + "def get" + self.name + "(self,")
        tabs = tabs + self.TAB
        spaces = ' ' * (len(lines[-1])  - len("self, "))
        objLines = [tabs + "obj =  { \n"]
        argStr = ''
        for (attr, attrInfo) in self.attrList:
            if attrInfo['isKey'] == 'True':
                argStr = "\n" + spaces + "%s," %(attr)
                assignmentStr = "%s" %(attr)

                if isNumericAttr(attrInfo):
                    #argStr = "\n" + spaces + "%s=%d," %(attr,int(attrInfo['default'].lstrip()))
                    assignmentStr = "int(%s)" %(attr)
                elif isBoolean(attrInfo['type']):
                    #argStr = "\n" + spaces + "%s=%s," %(attr, boolFromString(attrInfo['default'].lstrip()))
                    assignmentStr = "True if %s else False" %(attr)

                lines.append(argStr)
                objLines.append(tabs+tabs + "\'%s\' : %s,\n" %(attr, assignmentStr))


        lines[-1] = lines[-1][0:lines[-1].find(',')]
        lines.append("):\n")
        objLines.append(tabs + tabs+"}\n")
        lines = lines + objLines
        if self.name.endswith('State'):
            objName = self.name[:-5]
        else:
            objName = self.name
        lines.append (tabs + "reqUrl =  " + urlPath + " + " + "\'%s\'\n" %(objName))
        lines.append(tabs + "if self.authenticate == True:\n")
        lines.append(tabs + tabs + "r = requests.get(reqUrl, data=json.dumps(obj), headers=headers, timeout=self.timeout, auth=(self.user, self.passwd), verify=False) \n")
        lines.append(tabs + "else:\n")
        lines.append(tabs + tabs + "r = requests.get(reqUrl, data=json.dumps(obj), headers=headers, timeout=self.timeout) \n")
        lines.append(tabs + "return r\n")
        fileHdl.writelines(lines)

    def createGetAllMethod (self, fileHdl, urlPath):
        tabs = self.TAB
        lines = [ "\n"+ tabs + "def getAll" + self.name+"s" + "(self):\n"]
        tabs = tabs + self.TAB
        if 'r' in self.access:
            if self.name.endswith('State'):
                objName = self.name[:-5]
            else:
                objName = self.name
        else:
            objName = self.name
        lines.append (tabs + "return self.getObjects(\'%s\', %s)\n\n" %(objName, urlPath))
        fileHdl.writelines(lines)

    def createTblPrintAllMethod(self, fileHdl):
        tabs = self.TAB
        lines = []
        lines.append("\n"+ tabs + "def print" + self.name + "s(self, addHeader=True, brief=None):\n")
        tabs = tabs + self.TAB

        lines.append(tabs + "header = []; rows = []\n")
        lines.append(tabs + "if addHeader:\n")
        for (attr, attrInfo) in self.attrList:
            lines.append(tabs + self.TAB + "header.append(\'%s\')\n" %(attr))
        lines.append("\n")
        lines.append(tabs + "objs = self.swtch.getAll%ss()\n" %(self.name))
        lines.append(tabs + "for obj in objs:\n")
        lines.append(tabs + self.TAB + "o = obj['Object']\n")
        lines.append(tabs + self.TAB + "values = []\n")
        for (attr, attrInfo) in self.attrList:
            lines.append(tabs + self.TAB + "values.append(\'%%s\' %% o[\'%s\'])\n" %(attr))

        lines.append(tabs + self.TAB + "rows.append(values)\n")
        lines.append(tabs + "self.tblPrintObject(\'%s\', header, rows)\n\n" %(self.name))
        fileHdl.writelines(lines)

    def createTblPrintMethod(self, fileHdl):
        tabs = self.TAB
        lines = []
        argStr = ''
        for (attr, attrInfo) in self.attrList:
            if attrInfo['isKey'] == 'True':
                argStr += "%s," %(attr)


        lines.append("\n"+ tabs + "def print" + self.name + "(self, %s addHeader=True, brief=None):\n" %argStr)
        tabs = tabs + self.TAB

        lines.append(tabs + "header = []; rows = []\n")
        lines.append(tabs + "if addHeader:\n")
        for (attr, attrInfo) in self.attrList:
            lines.append(tabs + self.TAB + "header.append(\'%s\')\n" %(attr))
        lines.append("\n")
        lines.append(tabs + "rawobj = self.swtch.get%s(" %(self.name))
        #tabs = tabs + self.TAB
        spaces = ' ' * (len(lines[-1]))
        argStr = ''
        for (attr, attrInfo) in self.attrList:
            if attrInfo['isKey'] == 'True':
                argStr = "\n" + spaces + "%s," %(attr)
                assignmentStr = "%s" %(attr)

                if isNumericAttr(attrInfo):
                    #argStr = "\n" + spaces + "%s=%d," %(attr,int(attrInfo['default'].lstrip()))
                    assignmentStr = "int(%s)" %(attr)
                elif isBoolean(attrInfo['type']):
                    #argStr = "\n" + spaces + "%s=%s," %(attr, boolFromString(attrInfo['default'].lstrip()))
                    assignmentStr = "True if %s else False" %(attr)

                lines.append(argStr)

        lines[-1] = lines[-1][0:lines[-1].find(',')]
        lines.append(")\n")
        lines.append(tabs + "if rawobj.status_code in self.httpSuccessCodes:\n")
        lines.append(tabs + self.TAB + "obj = rawobj.json()\n")
        lines.append(tabs + self.TAB + "o = obj['Object']\n")
        lines.append(tabs + self.TAB + "values = []\n")
        for (attr, attrInfo) in self.attrList:
            lines.append(tabs + self.TAB + "values.append(\'%%s\' %% o[\'%s\'])\n" %(attr))

        lines.append(tabs + self.TAB + "rows.append(values)\n")
        lines.append(tabs + self.TAB + "self.tblPrintObject(\'%s\', header, rows)\n\n" %(self.name))

        lines.append(tabs + "else:\n")
        lines.append(tabs + self.TAB + "print rawobj.content\n")
        fileHdl.writelines(lines)

    #This function will print both config and state Obj attrs
    def createCombinedTblPrintAllMethod(self, fileHdl, cfgObjName, cfgObjAttrs):
        tabs = self.TAB
        lines = []
        lines.append("\n"+ tabs + "def printCombined" + self.name + "s(self, addHeader=True, brief=None):\n")
        tabs = tabs + self.TAB

        lines.append(tabs + "header = []; rows = []\n")
        lines.append(tabs + "if addHeader:\n")
        stateObjAttrs = []
        for (attr, attrInfo) in self.attrList:
            #Create list of attrs that have been processed already
            stateObjAttrs.append(attr)
            lines.append(tabs + self.TAB + "header.append(\'%s\')\n" %(attr))
        for (attr, attrInfo) in cfgObjAttrs:
            if not (attr in stateObjAttrs):
                lines.append(tabs + self.TAB + "header.append(\'%s\')\n" %(attr))
        lines.append("\n")
        lines.append(tabs + "objs = self.swtch.getAll%ss()\n" %(self.name))
        lines.append(tabs + "for obj in objs:\n")
        lines.append(tabs + self.TAB + "o = obj['Object']\n")
        lines.append(tabs + self.TAB + "values = []\n")
        for (attr, attrInfo) in self.attrList:
            lines.append(tabs + self.TAB + "values.append(\'%%s\' %% o[\'%s\'])\n" %(attr))
        lines.append(tabs + self.TAB + "r = self.swtch.get" + cfgObjName + "(")
        argStr = ''
        for (attr, attrInfo) in self.attrList:
            if attrInfo['isKey'] == 'True':
                argStr = argStr + "o[\'%s\'], " %(attr)
        argStr = argStr[:-2] + ')'
        lines.append(argStr)
        lines.append('\n' + tabs + self.TAB + "if r.status_code in self.httpSuccessCodes:\n")
        lines.append(tabs + self.TAB + self.TAB + "o = r.json()['Object']\n")
        for (attr, attrInfo) in cfgObjAttrs:
            if not (attr in stateObjAttrs):
                lines.append(tabs + self.TAB + self.TAB + "values.append(\'%%s\' %% o[\'%s\'])\n" %(attr))
        lines.append(tabs + self.TAB + "rows.append(values)\n")
        lines.append(tabs + "self.tblPrintObject(\'%s\', header, rows)\n\n" %(self.name))
        fileHdl.writelines(lines)

    def writeAllPrintMethods(self, fileHdl):
        self.createTblPrintAllMethod(fileHdl)
        self.createTblPrintMethod(fileHdl)

    def writeAllMethods (self, fileHdl):
        self.createGetMethod(fileHdl, 'self.stateUrlBase')
        self.createGetByIdMethod(fileHdl, 'self.stateUrlBase')
        self.createGetAllMethod(fileHdl, 'self.stateUrlBase')

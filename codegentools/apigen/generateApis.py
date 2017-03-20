import os
import json
from flexObject import FlexObject
from flexConfigObject import FlexConfigObject
from flexStateObject import FlexStateObject
from flexActionObject import FlexActionObject

class apiGenie (object) :
    def __init__ (self, outputDir, objDescriptors, attrDescriptionsDir) :
        self.outputDir = outputDir
        self.objDescriptors = objDescriptors
        self.attrBase = attrDescriptionsDir
        self.objDict = {}
        self.buildObjects() 

    def buildObjects (self) :
        for desc  in self.objDescriptors:
            with open(desc) as fileHdl:
                objMembersData = json.load(fileHdl)
                for objName, objInfo in objMembersData.iteritems():
                    canCreate = True
                    if objInfo['autoCreate'] == True:
                        canCreate = False
                    if 'w' in str(objInfo['access']):
                        self.objDict[objName] = FlexConfigObject (objName, 
                                                                  objInfo['access'],
                                                                  objInfo['multiplicity'],
                                                                  canCreate,
                                                                  self.attrBase + objName + "Members.json"
                                                                  )
                    elif 'r' in str(objInfo['access']):
                        self.objDict[objName] = FlexStateObject  (objName,
                                                                  objInfo['access'],
                                                                  objInfo['multiplicity'],
                                                                  canCreate,
                                                                  self.attrBase + objName + "Members.json"
                                                                  )
                    elif 'x' in str(objInfo['access']):
                        self.objDict[objName] = FlexActionObject (objName,
                                                                  objInfo['access'],
                                                                  objInfo['multiplicity'],
                                                                  canCreate,
                                                                  self.attrBase + objName + "Members.json"
                                                                  )
    def writeApiCode(self) :
        filePath = ''
        basePath= os.getenv('SR_CODE_BASE')
        if basePath!= None:
            filePath = basePath + '/reltools/codegentools/apigen/'
        outputFile = self.outputDir + 'flexswitchV2.py'
        with open(outputFile, 'w+') as fileHdl:
            with open(filePath + 'baseCode.txt', 'r') as base:
                fileHdl.writelines(base.readlines())
            for objName, obj in self.objDict.iteritems():
                obj.writeAllMethods(fileHdl)

        outputFile = self.outputDir + 'flexprintV2.py'
        with open(outputFile, 'w+') as fileHdl:
            with open(filePath + 'baseShowCode.txt', 'r') as base:
                fileHdl.writelines(base.readlines())
            for objName, obj in self.objDict.iteritems():
                obj.writeAllPrintMethods(fileHdl)
                #Generate a combined print method once for all objects
                if objName.endswith('State'):
                    cfgObjName = objName[:-5]
                    if self.objDict.has_key(cfgObjName):
                        obj.createCombinedTblPrintAllMethod(fileHdl, cfgObjName, self.objDict[cfgObjName].attrList)


if __name__ == '__main__':
    baseDir = os.getenv('SR_CODE_BASE',None)
    if not baseDir:
        print 'Environment variable SR_CODE_BASE is not set'
    
    objDescriptors = [ baseDir + '/snaproute/src/models/objects/' + 'genObjectConfig.json',
                       baseDir + '/snaproute/src/models/actions/' + 'genObjectAction.json']
    attrDescriptorsLocation = baseDir+'/reltools/codegentools/._genInfo/'
    outputDir = baseDir+'/snaproute/src/flexSdk/py/'
    gen = apiGenie( outputDir, objDescriptors, attrDescriptorsLocation)
    gen.writeApiCode()

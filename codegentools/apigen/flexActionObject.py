import json
import re
from flexObject import FlexObject, isNumericAttr, isBoolean, boolFromString, isListAttr
class FlexActionObject(FlexObject) :
    def createActionMethod(self, fileHdl):
        tabs = self.TAB
        #lines = [ "\n"+ tabs + "@processReturnCode"]
        lines = []
        lines.append( "\n"+ tabs + "def execute" + self.name + "(self,")
        docLines = [ "\n" + tabs + "\"\"\"" +"\n" + tabs + ".. automethod :: execute%s(self,\n" %(self.name)]
        #docLines.append("\n"+ tabs + "Parameters")
        #docLines.append("\n"+ tabs + "----------"+"\n")
        tabs = tabs + self.TAB
        spaces = ' ' * (len(lines[-1])  - len("self, "))
        objLines = [tabs + "obj =  { \n"]
        for (attr, attrInfo) in self.attrList:
            assignmentStr = ''
            argStr = ''
            docStr = tabs + ":param %s %s : %s " %(attrInfo['type'], attr, attrInfo['description'])
            if attrInfo['isDefaultSet'] == 'True':
                if isNumericAttr(attrInfo):
                    if attrInfo['isKey'] != 'True':
                        argStr = "\n" + spaces + "%s=%d," %(attr,int(attrInfo['default'].lstrip()))
                        assignmentStr = "int(%s)" %(attr)
                    else:
                        assignmentStr = "int(%s)" %(int(attrInfo['default'].lstrip()))
                elif isBoolean(attrInfo['type']):
                    if attrInfo['isKey'] != 'True':
                        argStr = "\n" + spaces + "%s=%s," %(attr, boolFromString(attrInfo['default'].lstrip()))
                        assignmentStr = "True if %s else False" %(attr)
                    else:
                        assignmentStr = "%s" %(boolFromString(attrInfo['default'].lstrip()))
                elif isListAttr(attrInfo):
                    if attrInfo['isKey'] != 'True':
                        argStr = "\n" + spaces + "%s=[]," %(attr)
                        assignmentStr = "%s" %(attr)
                    else:
                        assignmentStr = "'%s'" %(attrInfo['default'].lstrip())
                else:
                    if attrInfo['isKey'] != 'True':
                        argStr = "\n" + spaces + "%s=\'%s\'," %(attr,attrInfo['default'].lstrip())
                        assignmentStr = "%s" %(attr)
                    else:
                        assignmentStr = "'%s'" %(attrInfo['default'].lstrip())
            else:
                if isNumericAttr(attrInfo):
                    assignmentStr = "int(%s)" %(attr)
                elif isBoolean(attrInfo['type']):
                    assignmentStr = "True if %s else False" %(attr)
                else:
                    assignmentStr = "%s" %(attr)
                argStr = "\n" + spaces + "%s," %(attr)
            docLines.append(docStr +  attrInfo['description'] + "\n")

            lines.append(argStr)
            objLines.append(tabs+tabs + "\'%s\' : %s,\n" %(attr, assignmentStr))

        lines[-1] = lines[-1][0:lines[-1].find(',')]
        lines.append("):\n")
        objLines.append(tabs + tabs+"}\n")
        docLines.append("\n" + "\t\"\"\"" )
        lines = docLines + lines
        lines = lines + objLines
        lines.append (tabs + "reqUrl =  self.actionUrlBase+" +"\'%s\'\n" %(self.name))
        lines.append(tabs + "if self.authenticate == True:\n")
        lines.append(tabs + tabs + "r = requests.post(reqUrl, data=json.dumps(obj), headers=headers, auth=(self.user, self.passwd), verify=False) \n")
        lines.append(tabs + "else:\n")
        lines.append(tabs + tabs + "r = requests.post(reqUrl, data=json.dumps(obj), headers=headers) \n")
        lines.append(tabs + "return r\n")
        fileHdl.writelines(lines)

    def writeAllMethods (self, fileHdl):
        self.createActionMethod(fileHdl)

    def writeAllPrintMethods (self, fileHdl):
        pass

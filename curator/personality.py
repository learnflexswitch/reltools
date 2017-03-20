import os
import sys 
import json
import logging

class FlexPersonality (object):
    knobs = { 'Asic'   : '',
              'Distro' : '',
              'DeviceMgmt' : '',
              'MgmtIf' : 'ma1',
              'DisabledDaemons' : []
            }

    def __init__ (self,  platform = None, asic = None, distro = None):
        logging.basicConfig(stream=sys.stderr)
        self.log = logging.getLogger("System Personalisation")
        self.log.setLevel(logging.DEBUG)

    def performBuildTimeCustomization(self, pkgName):
        self.log.debug(' Customizing ')
        if pkgName:
            baseDir = os.getenv('SR_CODE_BASE', None)
            if baseDir:
                tuningDir = baseDir + '/snaproute/src/'+ pkgName
                self.customizeSystemProfile(tuningDir)
        return True

    def customizeSystemProfile (self, tuneDir):
        with open(tuneDir + '/opt/flexswitch/params/systemProfile.json', 'r') as fHdl:
            info = json.load(fHdl)

        info['MgmtIf'] = self.knobs['MgmtIf']
        dmnList = []
        for dmn in info['Daemons']:
            if dmn['Name'] in  self.knobs['DisabledDaemons']:
                dmn['Enabled'] = False
            dmnList.append(dmn)

        info['Daemons'] = dmnList
        with open(tuneDir + '/opt/flexswitch/params/systemProfile.json', 'w+') as fHdl:
            json.dump(info, fHdl, sort_keys=True, indent=4, separators=(',', ': '))

if __name__ == "__main__":
    pass



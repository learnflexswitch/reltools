import os
import sys 
import time
import json
import logging
from personality import FlexPersonality

class Voyager(FlexPersonality):

    def performBuildTimeCustomization(self):
        self.log.debug(' Customizing ')
        return True

if __name__ == "__main__":
    pass



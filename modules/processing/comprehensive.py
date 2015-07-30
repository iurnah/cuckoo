# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import logging
import datetime

from lib.cuckoo.common.abstracts import Processing
from lib.cuckoo.common.config import Config
from lib.cuckoo.common.netlog import NetlogParser, BsonParser
from lib.cuckoo.common.utils import convert_to_printable, logtime
from lib.cuckoo.common.utils import cleanup_value
from modules.processing import TargetInfo

log = logging.getLogger(__name__)

class Metadata:

    def __init__(self):
        self.metadata = {}
    def run(self):
        # return the object targetinfo, which is all about the file
        targetinof = TargetInfo().run() 



class Comprehesive(Processing):
    """obtain a complete set of feature for dynamic analysis samples in cuckoo
    sandbox
    """
    key = "comprehensive"
        
    def __init__(self):
        self.comprehensive = {}

    def run(self):
        # return the metadata about the target and the analysis
        metadata = Metadata.run()
        self.comprehensive.update(metadata)

        # return the behaviors of the dynamic analysis 
        #behavior = Behavior.run()
        #self.comprehensive.update(behavior)
    
        return self.comprehensive 

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
from modules.processing.targetinfo import TargetInfo
from modules.processing.analysisinfo import AnalysisInfo 
from modules.processing.virustotal import VirusTotal 

log = logging.getLogger(__name__)

class Metadata:
    "put together the meta infomation about the analyzed file" 
    def __init__(self, analysispath, task):
        self.metadata = {}
        self.analysis_path = analysispath
        self.task = task

    def run(self):
               
        # analysis info for current run of the sample 
        analysisinfo_module=AnalysisInfo()

        analysisinfo_module.set_path(self.analysis_path)
        analysisinfo_module.set_task(self.task)

        analysisinfo=analysisinfo_module.run()
        machineinfo=dict(
                analysisid=analysisinfo["id"],
                started=analysisinfo["started"] ,
                shutdown=analysisinfo["ended"],
                duration=analysisinfo["duration"],
                version=analysisinfo["version"],
                manager=analysisinfo["machine"]["manager"],
                guest=analysisinfo["machine"]["name"]
                )
        self.metadata.update(machine=machineinfo)

        # targetinfo, the testing file
        targetinfo_module=TargetInfo()

        targetinfo_module.set_path(self.analysis_path)
        targetinfo_module.set_task(self.task)

        targetinfo = targetinfo_module.run() 
        self.metadata.update(dict(
            name=targetinfo["file"]["name"],
            filetype=targetinfo["file"]["type"],
            size=targetinfo["file"]["size"],
            sha256=targetinfo["file"]["sha256"],
            md5=targetinfo["file"]["md5"]
            )) 
            
        # virustotal info about the file
        virustotal_module = VirusTotal()

        options = Config("processing").get("comprehensive")

        virustotal_module.set_path(self.analysis_path)
        virustotal_module.set_task(self.task)
        virustotal_module.set_options(options)
        
        virustotalinfo = virustotal_module.run()
        virustotalval=dict(
                date=virustotalinfo["scan_date"],
                permalink=virustotalinfo["permalink"],
                positives=virustotalinfo["positives"],
                total=virustotalinfo["total"],
                scans=virustotalinfo["scans"]
                )
        self.metadata.update(virustotal=virustotalval)
            
        return self.metadata 

class Behavior:
    """Put together as many behavior infomation as you can"""
    
    def __init__(self, analysis_path, task):
        self.analysis_path=analysis_path
        self.task=task
        self.processes = {}
        self.fs = {}
        self.registry = {}
        self.service = {}
        self.mutex = {}
        self.network = {}
    
    def apicall_event(self, call):
        """take a apicall and assign as one of the behavior entry"""
        def _load_args(call):
            res = {}
            for argument in call["arguments"]:
                res[argument["name"]] = argument["value"]

            return res

        def _generic_handle_details(self, call, item):
            event = None
            if call["api"] in item["apis"]:
                args = _load_args(call)

                event = {

                }
        #TODO:

    def event_behavior(self, call, process):
        """alk through each calls and extract the behavior infomation."""
        
        event = self.apicall_event(call)
        # file system

    def run(self):
        """return the behaviors"""

        return {"file":self.fs, "registry":self.registry,
                "service":self.service, "mutex":self.mutex, "network":self.network } 

        
class Comprehesive(Processing):
    """obtain a complete set of feature for dynamic analysis samples in cuckoo
    sandbox
    """
    key = "comprehensive"
        
    def __init__(self):
        self.comprehensive = {}

    def run(self):
        # return the metadata about the target and the analysis
        metadata = Metadata(self.analysis_path, self.task).run()
        self.comprehensive.update(metadata)

        # doing the behavior analysis 
        behavior = {}
        behavior["processes"] = Processes(self.logs_path).run()
        behavior_i = Behavior(self.analysis_path, self.task)

        for process in behavior["processes"]:
            for call in process["calls"]:
                behavior_i.event_behavior(call, process)

        behaviors = Behavior.run()
        self.comprehensive.update(behaviors)
    
        return self.comprehensive 

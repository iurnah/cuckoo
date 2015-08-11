# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import logging
import datetime
import re
import socket
import struct
import tempfile
import urlparse

from lib.cuckoo.common.abstracts import Processing
from lib.cuckoo.common.config import Config
from lib.cuckoo.common.netlog import NetlogParser, BsonParser
from lib.cuckoo.common.utils import convert_to_printable, logtime
from lib.cuckoo.common.utils import cleanup_value
#from lib.cuckoo.common.dns import resolve
#from lib.cuckoo.common.irc import ircMessage
#from lib.cuckoo.common.objects import File
from lib.cuckoo.common.exceptions import CuckooProcessingError
from modules.processing.targetinfo import TargetInfo
from modules.processing.analysisinfo import AnalysisInfo 
from modules.processing.virustotal import VirusTotal 
from modules.processing.network import NetworkAnalysis

log = logging.getLogger(__name__)

def fix_key(key):
    """Fix a registry key to have it normalized.
    @param key: raw key
    @returns: normalized key
    """
    res = key
    if key.lower().startswith("registry\\machine\\"):
        res = "HKEY_LOCAL_MACHINE\\" + key[17:]
    elif key.lower().startswith("registry\\user\\"):
        res = "HKEY_USERS\\" + key[14:]
    elif key.lower().startswith("\\registry\\machine\\"):
        res = "HKEY_LOCAL_MACHINE\\" + key[18:]
    elif key.lower().startswith("\\registry\\user\\"):
        res = "HKEY_USERS\\" + key[15:]

    return res


class ParseProcessLog(list):
    """Parses process log file."""

    def __init__(self, log_path):
        """@param log_path: log file path."""
        self._log_path = log_path
        self.fd = None
        self.parser = None

        self.process_id = None
        self.process_name = None
        self.parent_id = None
        self.first_seen = None
        self.calls = self
        self.lastcall = None
        self.call_id = 0

        if os.path.exists(log_path) and os.stat(log_path).st_size > 0:
            self.parse_first_and_reset()

    def parse_first_and_reset(self):
        self.fd = open(self._log_path, "rb")

        if self._log_path.endswith(".bson"):
            self.parser = BsonParser(self)
        elif self._log_path.endswith(".raw"):
            self.parser = NetlogParser(self)
        else:
            self.fd.close()
            self.fd = None
            return

        # Get the process information from file to determine
        # process id (file names.)
        while not self.process_id:
            self.parser.read_next_message()

        self.fd.seek(0)

    def read(self, length):
        if not length:
            return ''
        buf = self.fd.read(length)
        if not buf or len(buf) != length:
            raise EOFError()
        return buf

    def __iter__(self):
        #import inspect
        #log.debug('iter called by this guy: {0}'.format(inspect.stack()[1]))
        return self

    def __repr__(self):
        return "<ParseProcessLog log-path: %r>" % self._log_path

    def __nonzero__(self):
        return self.wait_for_lastcall()

    def reset(self):
        self.fd.seek(0)
        self.lastcall = None
        self.call_id = 0

    def compare_calls(self, a, b):
        """Compare two calls for equality. Same implementation as before netlog.
        @param a: call a
        @param b: call b
        @return: True if a == b else False
        """
        if a["api"] == b["api"] and \
                a["status"] == b["status"] and \
                a["arguments"] == b["arguments"] and \
                a["return"] == b["return"]:
            return True
        return False

    def wait_for_lastcall(self):
        while not self.lastcall:
            try:
                if not self.parser.read_next_message():
                    return False
            except EOFError:
                return False

        return True

    def next(self):
        if not self.fd:
            raise StopIteration()

        if not self.wait_for_lastcall():
            self.reset()
            raise StopIteration()

        nextcall, self.lastcall = self.lastcall, None

        self.wait_for_lastcall()
        while self.lastcall and self.compare_calls(nextcall, self.lastcall):
            nextcall["repeated"] += 1
            self.lastcall = None
            self.wait_for_lastcall()

        nextcall["id"] = self.call_id
        self.call_id += 1

        return nextcall

    def log_process(self, context, timestring, pid, ppid, modulepath, procname):
        self.process_id, self.parent_id, self.process_name = pid, ppid, procname
        self.first_seen = timestring

    def log_thread(self, context, pid):
        pass

    def log_anomaly(self, subcategory, tid, funcname, msg):
        self.lastcall = dict(thread_id=tid, category="anomaly", api="",
                             subcategory=subcategory, funcname=funcname,
                             msg=msg)

    def log_call(self, context, apiname, category, arguments):
        apiindex, status, returnval, tid, timediff = context

        current_time = self.first_seen + datetime.timedelta(0, 0, timediff*1000)
        timestring = logtime(current_time)

        self.lastcall = self._parse([timestring,
                                     tid,
                                     category,
                                     apiname,
                                     status,
                                     returnval] + arguments)

    def log_error(self, emsg):
        log.warning("ParseProcessLog error condition on log %s: %s", str(self._log_path), emsg)

    def _parse(self, row):
        """Parse log row.
        @param row: row data.
        @return: parsed information dict.
        """
        call = {}
        arguments = []

        try:
            timestamp = row[0]    # Timestamp of current API call invocation.
            thread_id = row[1]    # Thread ID.
            category = row[2]     # Win32 function category.
            api_name = row[3]     # Name of the Windows API.
            status_value = row[4] # Success or Failure?
            return_value = row[5] # Value returned by the function.
        except IndexError as e:
            log.debug("Unable to parse process log row: %s", e)
            return None

        # Now walk through the remaining columns, which will contain API
        # arguments.
        for index in range(6, len(row)):
            argument = {}

            # Split the argument name with its value based on the separator.
            try:
                arg_name, arg_value = row[index]
            except ValueError as e:
                log.debug("Unable to parse analysis row argument (row=%s): %s", row[index], e)
                continue

            argument["name"] = arg_name

            argument["value"] = convert_to_printable(cleanup_value(arg_value))
            arguments.append(argument)

        call["timestamp"] = timestamp
        call["thread_id"] = str(thread_id)
        call["category"] = category
        call["api"] = api_name
        call["status"] = bool(int(status_value))

        if isinstance(return_value, int):
            call["return"] = "0x%.08x" % return_value
        else:
            call["return"] = convert_to_printable(cleanup_value(return_value))

        call["arguments"] = arguments
        call["repeated"] = 0

        return call

class Processes:
    """Processes analyzer."""

    def __init__(self, logs_path):
        """@param  logs_path: logs path."""
        self._logs_path = logs_path
        self.cfg = Config()

    def run(self):
        """Run analysis.
        @return: processes infomartion list.
        """
        results = []

        if not os.path.exists(self._logs_path):
            log.warning("Analysis results folder does not exist at path \"%s\".", self._logs_path)
            return results

        # TODO: this should check the current analysis configuration and raise a warning
        # if injection is enabled and there is no logs folder.
        if len(os.listdir(self._logs_path)) == 0:
            log.info("Analysis results folder does not contain any file or injection was disabled.")
            return results

        for file_name in os.listdir(self._logs_path):
            file_path = os.path.join(self._logs_path, file_name)

            if os.path.isdir(file_path):
                continue

            # Skipping the current log file if it's too big.
            if os.stat(file_path).st_size > self.cfg.processing.analysis_size_limit:
                log.warning("Behavioral log {0} too big to be processed, skipped.".format(file_name))
                continue

            # Invoke parsing of current log file.
            current_log = ParseProcessLog(file_path)
            if current_log.process_id is None:
                continue

            # If the current log actually contains any data, add its data to
            # the results list.
            results.append({
                "process_id": current_log.process_id,
                "process_name": current_log.process_name,
                "parent_id": current_log.parent_id,
                "first_seen": logtime(current_log.first_seen),
                "calls": current_log.calls,
            })

        # Sort the items in the results list chronologically. In this way we
        # can have a sequential order of spawned processes.
        results.sort(key=lambda process: process["first_seen"])

        return results

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
        self.handles = []
        self.filehandles = {}
        self.servicehandles = {}
        self.procedures = {}
        self.modules = {}
        self.hookhandles = {}
        self.keyhandles = {
            "0x80000000": "HKEY_CLASSES_ROOT\\",
            "0x80000001": "HKEY_CURRENT_USER\\",
            "0x80000002": "HKEY_LOCAL_MACHINE\\",
            "0x80000003": "HKEY_USERS\\",
            "0x80000004": "HKEY_PERFORMANCE_DATA\\",
            "0x80000005": "HKEY_CURRENT_CONFIG\\",
            "0x80000006": "HKEY_DYN_DATA\\"
        }
        self.fs = {
                "open":[],
                "read":[], 
                "create":[], 
                "delete":[], 
                "modify":[], 
                "move":[] 
            }
        self.service = {
                "openscmanager": [],
                "open": [],
                "start":[],
                "create":[],
                "delete":[],
                "modify":[]
            }
        self.registry = {
                "open":[],
                "create":[],
                "delete":[],
                "enum":[],
                "modify":[],
                "query":[],
                #"load":[],
                #"save":[],
                "close":[]
            }
        self.mutex = {
                "open": [],
                "create":[]
            }
        self.dlls = []
        self.network = {}
        self.processes = []
        self.hooks = []
        self.unhooks = []
        self.windows = []

    def _add_hookhandle(self, sethookret, procedureaddress):
        """ add a hookhandle to procedure mapping
        """
        self.hookhandles[sethookret] = self._get_procedure(procedureaddress)
        #print "ADD HOOKHANDLE: {0}.{1} ".format(sethookret, self._get_procedure(procedureaddress))

    def _get_hookhandle(self, hookhandle):
        """ get a procedure name from the database
        """
        #print "GET HOOKHANDLE: {0}.{1} ".format(hookhandle,self.hookhandles.get(hookhandle, ""))
        return self.hookhandles.get(hookhandle, hookhandle)

    def _add_procedure(self, mbase, name, base):
        """
        Add a procedure address
        """
        #print "ADD PROCEDURE: {0}:{1} ".format(self._get_loaded_module(mbase), name)
        self.procedures[base] = "{0}:{1}".format(self._get_loaded_module(mbase), name)

    def _get_procedure(self, base):
        return self.procedures.get(base, base)

    def _add_loaded_module(self, name, base):
        """
        Add a loaded module to the internal database
        """
        self.modules[base] = name

    def _get_loaded_module(self, base):
        """
        Get the name of a loaded module from the internal db
        """
        return self.modules.get(base, "")

    # Registry
    def _add_keyhandle(self, registry, subkey, handle):
        """
        @registry: returned, new handle
        @handle: handle to base key
        @subkey: subkey to add
        """
        if handle != 0 and handle in self.keyhandles:
            return self.keyhandles[handle]

        name = ""
        if registry and registry != "0x00000000" and \
                registry in self.keyhandles:
            name = self.keyhandles[registry]

        nkey = name + subkey
        nkey = fix_key(nkey)

        self.keyhandles[handle] = nkey

        return nkey

    def _remove_keyhandle(self, handle):
        key = self._get_keyhandle(handle)

        if handle in self.keyhandles:
            self.keyhandles.pop(handle)

        return key

    def _get_keyhandle(self, handle):
        return self.keyhandles.get(handle, "..UNKNOWN..")


    def _check_registry(self, registry, subkey, handle):
        for known_handle in self.handles:
            if handle != 0 and handle == known_handle["handle"]:
                return None

        name = ""

        if registry == 0x80000000:
            name = "HKEY_CLASSES_ROOT\\"
        elif registry == 0x80000001:
            name = "HKEY_CURRENT_USER\\"
        elif registry == 0x80000002:
            name = "HKEY_LOCAL_MACHINE\\"
        elif registry == 0x80000003:
            name = "HKEY_USERS\\"
        elif registry == 0x80000004:
            name = "HKEY_PERFORMANCE_DATA\\"
        elif registry == 0x80000005:
            name = "HKEY_CURRENT_CONFIG\\"
        elif registry == 0x80000006:
            name = "HKEY_DYN_DATA\\"
        else:
            for known_handle in self.handles:
                if registry == known_handle["handle"]:
                    name = known_handle["name"] + "\\"

        key = fix_key(name + subkey)
        self.handles.append({"handle": handle, "name": key})
        return key


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
                    "event":item["event"],
                    "object":item["object"],
                    "data":{}
                }

                for logname, dataname in item["args"]:
                    event["data"][logname] = args.get(dataname, "")
                event["data"]["regkey"] = ""

            return event

        def _generic_handle(self, data, call):
            """Generic handling of api calls."""
            for item in data:
                event = _generic_handle_details(self, call, item)
                if event:
                    return event

            return None

         # Generic handles
        def _add_handle(handles, handle, filename):
            handles[handle] = filename

        def _remove_handle(handles, handle):
            if handle in handles:
                handles.pop(handle)

        def _get_handle(handles, handle):
            return handles.get(handle)
       
        def _get_service_action(control_code):
            """@see: http://msdn.microsoft.com/en-us/library/windows/desktop/ms682108%28v=vs.85%29.aspx"""
            codes = {1: "stop",
                     2: "pause",
                     3: "continue",
                     4: "info"}

            default = "user" if control_code >= 128 else "notify"
            return codes.get(control_code, default)


        event = None

        gendat = [
            {
                "event": "create",
                "object": "file",
                "apis":[
                    "NtCreateFile",
                    ],
                "args":[ ("file", "FileName") ]
            },
            {
                "event": "open",
                "object": "file",
                "apis": [
                    "NtOpenFile",
                    ],
                "args": [ ("file", "FileName") ]
            },
            {
                "event": "read",
                "object": "file",
                "apis": [
                    "NtReadFile",
                    "NtQueryInformationFile",
                    ],
                "args": [("handle", "FileHandle")] 
            },
            {
                "event": "write",
                "object": "file",
                "apis": [
                    "NtWriteFile",
                    "NtSetInformationFile",
                    ],
                "args": [("handle", "FileHandle")]
            },
            {
                "event": "delete",
                "object": "file",
                "apis": [
                    "NtDeleteFile",
                    ],
                "args": [ ("file", "FileName") ]
            },
            {
                "event": "create",
                "object": "file",
                "apis":[
                    "CreateDirectoryW",
                    "CreateDirectoryExW",
                    ],
                "args":[ ("file", "DirectoryName") ]
            },
            {
                "event": "delete",
                "object": "file",
                "apis":[
                    "RemoveDirectoryA",
                    "RemoveDirectoryW",
                    ],
                "args":[ ("file", "DirectoryName") ]
            },
            {
                "event":"move",
                "object": "file",
                "apis": [
                    "MoveFileWithProgressW",
                ],
                "args": [
                    ("from", "ExistingFileName"),
                    ("to", "NewFileName")
                ]
            },
            # services
            {
                "event":"openscmanager",
                "object": "service",
                "apis": [
                    "OpenSCManagerA",
                    "OpenSCManagerW",
                ],
                "args": [
                    ("machine", "MachineName"),
                    ("servicedb", "DatabaseName")
                ]       
            },
            {
                "event":"open",
                "object": "service",
                "apis": [
                    "OpenServiceA",
                    "OpenServiceW",
                ],
                "args": [ ("servicename", "ServiceName") ]       
            },
            {
                "event":"start",
                "object": "service",
                "apis": [
                    "StartServiceA",
                    "StartServiceW",
                ],
                "args": [ ("handle", "ServiceHandle") ]       
            },
            {
                "event":"create",
                "object": "service",
                "apis": [
                    "CreateServiceA",
                    "CreateServiceW",
                ],
                "args": [
                    ("servicename", "ServiceName"),
                    ("binaryname", "BinaryPathName")
                ]       
            },           
            {
                "event":"delete",
                "object": "service",
                "apis": [
                    "DeleteService",
                ],
                "args": [ ("handle", "ServiceHandle") ]       
            },
            {
                "event":"modify",
                "object": "service",
                "apis": [
                    "ControlService",
                ],
                "args": [ 
                    ("handle", "ServiceHandle"),
                    ("controlcode", "ControlCode")
                ]       
            },
            # registry: for the same event, it should be same key for "args"
            {
                "event":"open",
                "object": "registry",
                "apis": [
                    "RegOpenKeyExA",
                    "RegOpenKeyExW",
                ],
                "args": [ 
                    ("registry", "Registry"),
                    ("subkey", "SubKey"),
                    ("handle", "Handle")
                ]   
            },
            {
                "event":"open",
                "object": "registry",
                "apis": [
                    "NtOpenKeyEx",
                    "NtOpenKey",
                ],
                "args": [ 
                    ("keyhandle", "KeyHandle"),
                    ("objectattr", "ObjectAttributes")
                ]   
            },
            {
                "event":"create",
                "object": "registry",
                "apis": [
                    "NtCreateKey",
                ],
                "args": [ 
                    ("keyhandle", "KeyHandle"),
                    ("objectattr", "ObjectAttributes")
                ]   
            },
            {
                "event":"create",
                "object": "registry",
                "apis": [
                    "RegCreateKeyExA",
                    "RegCreateKeyExW",
                ],
                "args": [ 
                    ("keyhandle", "Registery"),
                    ("subkey", "SubKey"),
                    ("handle", "Handle")
                ]   
            },
            {
                "event":"delete",
                "object": "registry",
                "apis": [
                    "RegDeleteKeyA",
                    "RegDeleteKeyW",
                ],
                "args": [ 
                    ("handle", "Handle"),
                    ("subkey", "SubKey")
                ]   
            },
            {
                "event":"delete",
                "object": "registry",
                "apis": [
                    "NtDeleteKey",  
                ],
                "args": [ 
                    ("keyhandle", "KeyHandle"),
                ]   
            },
            {
                "event":"delete",
                "object": "registry",
                "apis": [
                    "RegDeleteValueA",
                    "RegDeleteValueW",
                ],
                "args": [ 
                    ("handle", "Handle"),
                    ("valuname", "ValueName")
                ]   
            },
            {
                "event":"delete",
                "object": "registry",
                "apis": [
                    "NtDeleteValueKey",
                ],
                "args": [ 
                    ("keyhandle", "KeyHandle"),
                    ("valuname", "ValueName")
                ]   
            },
            {
                "event":"enum",
                "object": "registry",
                "apis": [
                    "RegEnumKeyW",
                    "RegEnumKeyExA",
                    "RegEnumKeyExW",
                ],
                "args": [ 
                    ("handle", "Handle"),
                    ("name", "Name")# subkey string 
                ]   
            },
            { 
                "event":"enum",
                "object": "registry",
                "apis": [
                    "RegEnumValueA",
                    "RegEnumValueW",
                ],
                "args": [ 
                    ("handle", "Handle"),
                    ("valuename", "ValueName")
                ]   
            },
            {
                "event":"enum",
                "object": "registry",
                "apis": [
                    "NtEnumerateKey",
                    "NtEnumerateValueKey",
                ],
                "args": [ 
                    ("keyhandle", "KeyHandle"),
                ]   
            },
            {
                "event":"query",
                "object": "registry",
                "apis": [
                    "RegQueryValueExA",    
                    "RegQueryValueExW",    
                ],
                "args":[
                    ("handle", "Handle"),
                    ("valuname", "ValueName"),
                ]
            },
            {
                "event":"query",
                "object": "registry",
                "apis": [
                    "NtQueryKey",    
                    "NtQueryValueKey",    
                    "NtQueryMultipleValueKey"
                ],
                "args":[
                    ("keyhandle", "keyHandle"),
                    ("valuname", "ValueName")
                ]
            },
            {
                "event":"modify",
                "object": "registry",
                "apis": [
                    "NtRenameKey",
                ],
                "args": [ 
                    ("keyhandle", "KeyHandle"),
                    ("newname", "NewName"),
                ]   
            },
            {
                "event":"modify",
                "object": "registry",
                "apis": [
                    "NtReplaceKey",
                ],
                "args": [ 
                    ("keyhandle", "KeyHandle"),
                    ("newhivefilekey", "NewHiveFileKey")
                ]   
            },
            {
                "event":"modify",
                "object": "registry",
                "apis": [
                    "RegSetValueExA",
                    "RegSetValueExW",
                ],
                "args": [ 
                    ("handle", "Handle"),
                    ("valuname", "ValueName")
                ]   
            },
            {
                "event":"modify",
                "object": "registry",
                "apis": [
                    "NtSetValueKey",
                ],
                "args": [ 
                    ("keyhandle", "KeyHandle"),
                    ("valuename", "ValueName")
                ]   
            },
            {# Done
                "event":"load",
                "object": "registry",
                "apis": [
                    "NtLoadKey",
                    "NtLoadKey2",
                    "NtLoadKeyEx",
                ],
                "args": [ 
                    ("targetkey", "TargetKey"),
                    ("sourcefile", "SourceFile")
                ]   
            },
            {
                "event":"save",
                "object": "registry",
                "apis": [
                    "NtSaveKey",
                    "NtSaveKeyEx",
                ],
                "args": [ 
                    ("keyhandle", "KeyHandle"),
                    ("filehandle", "FileHandle")
                ]   
            },
            {
                "event":"close",
                "object": "registry",
                "apis": [
                    "RegCloseKey",
                ],
                "args": [ 
                    ("handle", "Handle"),
                ]   
            },
            {
                "event":"open",
                "object": "mutex",
                "apis": [
                    "NtOpenMutant",
                ],
                "args": [ ("mutexname", "MutexName") ]   
            },
            {
                "event":"create",
                "object": "mutex",
                "apis": [
                    "NtCreateMutant",
                ],
                "args": [ ("mutexname", "MutexName") ]   
            },
            # dlls
            {
                "event": "loaddll",
                "object": "dll",
                "apis":[
                    "LdrLoadDll",
                ],
                "args": [
                    ("file", "FileName"),
                    ("moduleaddress", "BaseAddress")
                ]
            },
            {
                "event": "loaddll",
                "object": "dll",
                "apis":[
                    "LdrGetDllHandle"
                ],
                "args": [
                    ("file", "FileName"),
                    ("modulehandle", "ModuleHandle")
                ]
            },
            # hooks
            {
                "event": "hook",
                "object": "module",
                "apis":[
                    "SetWindowsHookExA", 
                    "SetWindowsHookExW"
                ],
                "args": [
                    ("procedureaddress", "ProcedureAddress"),
                    ("moduleaddress", "ModuleAddress"),
                ]
            },
            {
                "event": "unhook",
                "object": "module",
                "apis":[
                    "UnhookWindowsHookEx"
                ],
                "args": [ ("hookhandle", "HookHandle") ]
            },
            {
                "event": "procedure",
                "object": "procedure",
                "apis":[
                    "LdrGetProcedureAddress"
                ],
                "args": []
            },
            {
                "event": "find",
                "object": "window",
                "apis": [
                    "FindWindowA",
                    "FindWindowW", 
                    "FindWindowExA",
                    "FindWindowExW"
                ],
                "args": [ ("windowname", "WindowName") ]
            },
        ]

        event = _generic_handle(self, gendat, call)
        args = _load_args(call)
        
        # add/remove the handle to the database and resolve hanld to name
        # fs
        if event and event["object"] == "file":
            if call["api"] in ["NtCreateFile", "NtOpenFile"]: 
                _add_handle(self.filehandles, args["FileHandle"], args["FileName"])
            elif call["api"] in ["NtReadFile","NtWriteFile","NtQueryInformationFile", "NtSetInformationFile"]:
                event["data"]["file"] = _get_handle(self.filehandles, args["FileHandle"])
            elif call["api"] in ["NtClose","CloseHandle"]:
                _remove_handle(self.filehandles, args["Handle"])
        # service
        if event and event["object"] == "service":
            if call["api"] in ["CreateServiceA", "CreateServiceW", "OpenServiceW", "OpenServiceA"]: 
                _add_handle(self.servicehandles, call["return"], args["ServiceName"])
            elif call["api"] in ["StartServiceA", "StartServiceW", "DeleteService", "ControlService"]:
                event["data"]["servicename"] = _get_handle(self.servicehandles, args["ServiceHandle"])
                if call["api"] in ["DeleteService"]:
                    _remove_handle(self.servicehandles, args["ServiceHandle"])
                elif call["api"] in ["ControlService"]:
                    event["data"]["action"] = _get_service_action(args["ControlCode"])
        # registry
        if event and event["object"] == "registry": #get regkey for open
            if call["api"] in ["RegOpenKeyExA", "RegOpenKeyExW", "RegCreateKeyExA", "RegCreateKeyExW"]:
                self._add_keyhandle(args.get("Registry", ""), args.get("SubKey", ""), args.get("Handle", ""))

                registry = 0
                subkey = ""
                handle = 0

                for argument in call["arguments"]:
                    if argument["name"] == "Registry":
                        registry = int(argument["value"], 16)
                    elif argument["name"] == "SubKey":
                        subkey = argument["value"]
                    elif argument["name"] == "Handle":
                        handle = int(argument["value"], 16)

                name = self._check_registry(registry, subkey, handle)
                if name: 
                    event["data"]["regkey"] = name 

            elif call["api"] in ["NtOpenKey","NtOpenKeyEx", "NtCreateKey"]:
                self._add_keyhandle(None, args.get("ObjectAttributes", ""), args.get("KeyHandle", ""))

                registry = -1
                subkey = ""
                handle = 0

                for argument in call["arguments"]:
                    if argument["name"] == "ObjectAttributes":
                        subkey = argument["value"]
                    elif argument["name"] == "KeyHandle":
                        handle = int(argument["value"], 16)

                name = self._check_registry(registry, subkey, handle)
                if name:
                    event["data"]["regkey"] = name

            elif call["api"] in ["RegDeleteKeyA", "RegDeleteKeyW", "NtDeleteKey" ]:
                if call["api"] == "NtDeleteKey":
                    event["data"]["regkey"] = self._get_keyhandle(args.get("KeyHandle", "UNKNOWN")) 
                else:
                    event["data"]["regkey"] = "{0}\\{1}".format(self._get_keyhandle(args.get("Handle", "UNKNOWN")), args.get("SubKey", ""))

            elif call["api"] in ["RegDeleteValueA", "RegDeleteValueW", "NtDeleteValueKey" ]:
                if call["api"] == "NtDeleteValueKey":
                    event["data"]["regkey"] = "{0}\\{1}".format(self._get_keyhandle(args.get("KeyHandle", "UNKNOWN")), args.get("ValueName", ""))
                else:
                    event["data"]["regkey"] = "{0}\\{1}".format(self._get_keyhandle(args.get("Handle", "UNKNOWN")), args.get("ValueName", ""))

            elif call["api"] in ["RegEnumKeyW", "RegEnumKeyExA", "RegEnumKeyExW"]:
                event["data"]["regkey"] = "{0}\\{1}".format(self._get_keyhandle(args.get("Handle", "UNKNOWN")), args.get("Name", ""))

            elif call["api"] in ["RegEnumValueA", "RegEnumValueW"]:
                event["data"]["regkey"] = "{0}\\{1}".format(self._get_keyhandle(args.get("Handle", "UNKNOWN")), args.get("ValueName", ""))

            elif call["api"] in ["NtEnumerateKey", "NtEnumerateValueKey"]:
                event["data"]["regkey"] = self._get_keyhandle(args.get("KeyHandle", "UNKNOWN")) 

            elif call["api"] in ["RegQueryValueExA", "RegQueryValueExW"]:
                event["data"]["regkey"] = "{0}\\{1}".format(self._get_keyhandle(args.get("Handle", "UNKNOWN")), args.get("ValueName", ""))

            elif call["api"] in [ "NtQueryKey", "NtQueryValueKey", "NtQueryMultipleValueKey"]:
                if call["api"] == "NtQueryKey":
                    event["data"]["regkey"] = self._get_keyhandle(args.get("KeyHandle", "UNKNOWN")) 
                else:
                    event["data"]["regkey"] = "{0}\\{1}".format(self._get_keyhandle(args.get("KeyHandle", "UNKNOWN")), args.get("ValueName", ""))

            elif call["api"] in [ "NtRenameKey" ]:
                event["data"]["regkey"] = "{0}\\{1}".format(self._get_keyhandle(args.get("KeyHandle", "UNKNOWN")), args.get("NewName", ""))

            elif call["api"] in ["NtReplaceKey"]:
                event["data"]["regkey"] = "{0}\\{1}".format(self._get_keyhandle(args.get("KeyHandle", "UNKNOWN")), args.get("NewHiveFileKey", ""))

            elif call["api"] in ["NtSetValueKey"]:
                    event["data"]["regkey"] = "{0}\\{1}".format(self._get_keyhandle(args.get("KeyHandle", "UNKNOWN")), args.get("ValueName", ""))

            elif call["api"] in ["RegCloseKey"]:
                self._remove_keyhandle(args.get("Handle", ""))

                handle = 0
                for argument in call["arguments"]:
                    if argument["name"] == "Handle":
                        handle = int(argument["value"], 16)

                if handle != 0:
                    for a in self.handles:
                        if a["handle"] == handle:
                            try:
                                self.handles.remove(a)
                            except ValueError:
                                pass
        # mutex
        # dlls
        if event and event["object"] == "dll": #build the module database
            if call["api"] in ["LdrGetDllHandle"] and call["status"]:
                self._add_loaded_module(args.get("FileName", ""), args.get("ModuleHandle", ""))

            elif call["api"] in ["LdrLoadDll"] and call["status"]:
                self._add_loaded_module(args.get("FileName", ""), args.get("BaseAddress", ""))

        # hooks
        if event and event["object"] == "module": #get the hooked module name
            if call["api"] in ["SetWindowsHookExA", "SetWindowsHookExW"]:
                event["data"]["hook"] = self._get_procedure(args.get("ProcedureAddress", ""))
                self._add_hookhandle(call.get("return"), args.get("ProcedureAddress", ""))
            elif call["api"] in ["UnhookWindowsHookEx"]: # handle to the hooked function
                event["data"]["unhook"] = self._get_hookhandle(args.get("HookHandle", ""))

        # auxiliary for resolving APIs 
        if event and call["status"] and call["api"] in ["LdrGetProcedureAddress"]:
            self._add_procedure(args.get("ModuleHandle", ""), args.get("FunctionName", ""), args.get("FunctionAddress", ""))
        
        # windows
            
        return event

    def event_behavior(self, call, process):
        """Walk through each calls and extract the behavior infomation."""
        
        # get the created processes
        new_process = process["process_name"]
        if new_process and new_process not in self.processes:
            self.processes.append(new_process)

        event = self.apicall_event(call)

        # fs
        if event and event["object"] == "file":
            if event["event"] == "open":
                if event["data"]["file"] not in self.fs["open"]:
                    self.fs["open"].append(event["data"]["file"]) 
            elif event["event"] == "read":
                if event["data"]["file"] not in self.fs["read"]:
                    self.fs["read"].append(event["data"]["file"]) 
            elif event["event"] == "create":
                if event["data"]["file"] not in self.fs["create"]:
                    self.fs["create"].append(event["data"]["file"]) 
            elif event["event"] == "delete":
                if event["data"]["file"] not in self.fs["delete"]:
                    self.fs["delete"].append(event["data"]["file"]) 
            elif event["event"] == "write":
                if event["data"]["file"] not in self.fs["modify"]:
                    self.fs["modify"].append(event["data"]["file"]) 
            elif event["event"] == "move":
                if event["data"]["to"] not in self.fs["move"]:
                    self.fs["move"].append(event["data"]["to"]) 
        # service
        elif event and event["object"] == "service":
            if event["event"] == "openscmanager":
                if event["data"]["servicedb"] not in self.service["openscmanager"]:
                    self.service["openscmanager"].append(event["data"]["servicedb"])
            elif event["event"] == "open":
                if event["data"]["servicename"] not in self.service["open"]:
                    self.service["open"].append(event["data"]["servicename"])
            elif event["event"] == "start":
                if event["data"]["servicename"] not in self.service["start"]:
                    self.service["start"].append(event["data"]["servicename"])
            elif event["event"] == "create":
                if event["data"]["servicename"] not in self.service["create"]:
                    self.service["create"].append(event["data"]["servicename"])
            elif event["event"] == "delete":
                if event["data"]["servicename"] not in self.service["delete"]:
                    self.service["delete"].append(event["data"]["servicename"])
            elif event["event"] == "modify":
                if event["data"]["servicename"] not in self.service["modify"]:
                    self.service["modify"].append(event["data"]["servicename"])
        # registry
        elif event and event["object"] == "registry":
            if event["event"] == "open":
                if event["data"]["regkey"] not in self.registry["open"]:
                    self.registry["open"].append(event["data"]["regkey"])
            elif event["event"] == "create":
                if event["data"]["regkey"] not in self.registry["create"]:
                    self.registry["create"].append(event["data"]["regkey"])
            elif event["event"] == "close":
                if event["data"]["regkey"] not in self.registry["close"]:
                    self.registry["close"].append(event["data"]["regkey"])
            elif event["event"] == "delete":
                if event["data"]["regkey"] not in self.registry["delete"]:
                    self.registry["delete"].append(event["data"]["regkey"])
            elif event["event"] == "enum":
                if event["data"]["regkey"] not in self.registry["enum"]:
                    self.registry["enum"].append(event["data"]["regkey"])
            elif event["event"] == "query":
                if event["data"]["regkey"] not in self.registry["query"]:
                    self.registry["query"].append(event["data"]["regkey"])
            elif event["event"] == "modify":
                if event["data"]["regkey"] not in self.registry["modify"]:
                    self.registry["modify"].append(event["data"]["regkey"])
        # mutex
        elif event and event["object"] == "mutex":
            if event["event"] == "open":
                if event["data"]["mutexname"] not in self.mutex["open"]:
                    self.mutex["open"].append(event["data"]["mutexname"])
            if event["event"] == "create":
                if event["data"]["mutexname"] not in self.mutex["create"]:
                    self.mutex["create"].append(event["data"]["mutexname"])
        # runtime dlls 
        elif event and event["object"] == "dll":
            if event["event"] == "loaddll":
                if event["data"]["file"] not in self.dlls:
                    self.dlls.append(event["data"]["file"])
        # hooks
        elif event and event["object"] == "module":
            if event["event"] == "hook":
                if event["data"]["hook"] not in self.hooks:
                    self.hooks.append(event["data"]["hook"])
            elif event["event"] == "unhook":
                if event["data"]["unhook"] not in self.unhooks:
                    self.unhooks.append(event["data"]["unhook"])
        # windows
        elif event and event["object"] == "window":
            if event["data"]["windowname"] and event["data"]["windowname"] not in self.windows:
                self.windows.append(event["data"]["windowname"])
            else:
                self.windows.append("UNIDENTIFIED")

    def run(self):
        """return the behaviors"""

        return {"file":self.fs, "registry":self.registry, "service":self.service, 
                "mutex":self.mutex, "processes": self.processes, "runtimedll":self.dlls, 
                "hooks": self.hooks, "unhooks": self.unhooks, "searchedwindow":self.windows} 
        
class Network:
    """network information include:
    TCP connections, DNS requrests, HTTP requests, UDP communications
    """
    key = "network"
    
    def __init__(self, analysis_path, task):
        self.analysis_path = analysis_path
        self.task = task
        self.results = {} 
        self.tcpdst = []
        self.udpdst = []
        self.dnssrv = []
        self.httpsrv = []

    def run(self):
        
        networkinfo = NetworkAnalysis()
        networkinfo.set_path(self.analysis_path)
        networkinfo.set_task(self.task)

        results = networkinfo.run() 

        # get the udp dst
        if results:
            for entry in results["udp"]:
                if entry:
                    if "192.168.56" not in entry["dst"]:
                        self.udpdst.append(entry["dst"])

            # get the tcp dst
            for entry in results["tcp"]:
                if entry: 
                    if "192.168.56" not in entry["dst"]:
                        self.tcpdst.append(entry["dst"])

            # get the DNS request
            for entry in results["dns"]:
                if entry: 
                    self.dnssrv.append(entry["request"])

            # get the http request
            for entry in results["http"]:
                if entry:
                    self.httpsrv.append(entry["dst"])
        
        self.results = {
                    "TCP connections": list(set(self.tcpdst)), 
                    "UDP connections": list(set(self.udpdst)),
                    "DNS requests": list(set(self.dnssrv)), 
                    "HTTP requests": list(set(self.httpsrv))
                }

        return self.results

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

        behaviors = behavior_i.run()
        self.comprehensive.update(behaviors)

        # Pass Pcap to get the network behaviors
        network_behaviors = Network(self.analysis_path, self.task).run()
        self.comprehensive.update(network_behaviors)

        return self.comprehensive 

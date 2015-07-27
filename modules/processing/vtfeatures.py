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

class FileSystem:
	"""file operations include:
	open, read, written, deleted, replaced 
	"""
	key = "filesystem"

    def __init__(self):
		self.fseid = 0
		self.filehandles = {}
        self.opened = []
        self.read = []
        self.written = []
        self.deleted = []
        self.replaced = []
		self.events = []
	
	def process_call(self, call):
		"""processing the logged api, and extract the file system 
		behaviors
		@return: file system behaviors json list 
		"""
		def load_args(call):
			""" Get the key:value pair api arguments
			"""
			res = {}
			for argument in call["arguments"]:
				res[argument["name"]] = argument["value"]

			return res
	
		def generic_handle_details(self, call, item):
			""" 
			@return: 
			"""
			event = None
			if call["api"] in item["apis"]:
				args = load_args(call)
				self.fseid += 1

				event = {
					"operation": item["operation"]
					"data": {}
						}
			for argkey, argval in item["args"]:
				event["data"][argkey] = args.get(argkey)
		
		def generic_handle(self, data, call):
			"""
			@return:
			"""
			for item in data:
				event = generic_handle_details(self, call, item)
				if event:
					return event

			return None

		def add_handle(handles, handle, filename):
			handles[handle] = filename

		def remove_handle(handles, handle):
			if handle in handles:
				handles.pop(handle)

		def get_handle(handles, handle):
			return handles.get(handle)

		event = None

		gendat = [
				{
					"operation": "open",
					"apis": [
						"NtOpenFile",
						"OpenFile",
						]
					"args": [ ("file", "FileName") ]
				},
				{
					"operation": "read",
					"apis": [
						"NtReadFile",
						"ReadFile",
						]
					"args": [("filehandle", "FileHandle")] 
				},
				{
					"operation": "write",
					"apis": [
						"URLDownloadToFileW",
						"URLDownloadToFileA",
						"NtWriteFile"
						]
					"args": [("filehandle", "FileHandle")]
				},
				{
					"operation": "delete",
					"apis": [
						"DeleteFileA",
						"DeleteFileW",
						"NtDeleteFile"
						]
					"args": [ ("file", "FileName") ]
				},
				{
					"operation": "replaced",
					"apis": [
						"MoveFileWithProgressW",
						"MoveFileExA",
						"MoveFileExW"
						]
					"args": [ 
						("from", "ExistingFileName"),
						("to", "NewFileName")	
					]
				},
			]

		# obtained the syscall with the generic handle (not the file path
		# string)
		event = generic_handle(self, gendat, call); 
		args = load_args(call)

		# obtain the file path string from the generic handles
		if event:
			if call["api"] in ["NtCreateFile", "NtOpenFile"]:
				add_handle(self.filehandles, args["FileHandle"], args["FileName"])
			elif call["api"] in ["CreateFileW"]:
				add_handle(self.filehandles, call["return"], args["FileName"])
			elif call["api"] in ["NtClose", "CloseHandle"]:
				remove_handle(self.filehandles, args["handle"])
			elif call["api"] in ["", ""]:
			elif call["api"] in ["", ""]:
			elif call["api"] in ["", ""]:
			elif call["api"] in ["", ""]:


	def apicall_process(self, call, process):
		"""call to the process_call method to get the fat 
		about the filesystem behaviors.
		"""
		# event is one of the filesystem events we are desired.
		event = self.process_call(call)
		# add the returned event to its caterogies. 
		if event:
			self.events.append(result)

	def run(self):
		""" return the dictionary of properly formated filesystem behaviors
		"""
		return self.results

class Network:
	"""network information include:
	TCP connections, DNS requrests, HTTP requests, UDP communications
	"""
	key = "network"

	pass

class Mutexes:
	"""mutexes information include:
	Created mutexes, Opened mutexes
	"""
	key = "mutexes"

	pass

class ProcInfo:
	"""processes operation include:
	Created processes, Terminated processes
	"""
	key = "procinfo"

	pass

class RunTimeDLL:
	"""run time loaded DLLs:
	Runtime DLLs
	"""
	key = "runtimedll"

	pass

class Misc():
	"""the rest
	"""
	key = "misc"
	pass

class VtFeatures(Processing):
	"""generate the feature for matching the virustotal json file """

	key = "vtfeature"
	pass

	def run(self):
		"""run the feature generation
		"""

		vtfeature = {}
		# get all the [pid].log
		vtfeature["processes"] = Processes(self.logs_path).run() 

		# feature categories
        instances = [
			FileSystem(),
			Network(),
			Mutexes(),
			ProcInfo(),
			RunTimeDLL(),
			Misc(),
		]

		# 	
		for process in vtfeature["processes"]:
			for call in process["calls"]
				for instance in instances:	
					try:
						instance.apicall_process(call, process)
					except:
						log.exception("Failure in generate feature \"%s\"", instance.key)
		
		for instance in instances:
			try:
				vtfeature[instance.key] = instance.run()
			except:
				log.exception("Failure in generate feature \"%s\"", instance.key)
		
		return vtfeature

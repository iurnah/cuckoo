# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import json
import codecs
import operator
import re

from lib.cuckoo.common.abstracts import Report
from lib.cuckoo.common.exceptions import CuckooReportError
from collections import OrderedDict

class VtFeatureDump(Report):
    """Saves analysis results in JSON format."""

    def run(self, results):
        """Writes report.
        @param results: Cuckoo results dict.
        @raise CuckooReportError: if fails to write report.
        """
        indent = self.options.get("indent", 4)
        encoding = self.options.get("encoding", "utf-8")

        vtfeature = OrderedDict()
        details = OrderedDict()
        categories = "" 

        compreobj = results["comprehensive"]

        wordcount = {}
        
        for k, v in compreobj["virustotal"]["scans"].iteritems():
            if v["result"]:
                words = re.split('\.|/| |:|!', v["result"])
                for word in words:
                    w = word.lower()
                    if w not in wordcount:
                        wordcount[w] = 1 
                    else:
                        wordcount[w] += 1

        sorted_wc = sorted(wordcount.iteritems(), key=operator.itemgetter(1))
        sorted_wc.reverse()
        i = 10
        for kk, vv in sorted_wc:
            if i:
                categories += "({}={})".format(kk, vv)
                i -= 1

        details = {
                "id":compreobj["sha256"],
                "categories": categories,
                "permurl":compreobj["virustotal"]["permalink"],
                "scorestr":"{0}/{1}".format(compreobj["virustotal"]["positives"],compreobj["virustotal"]["total"]),
                }

        vtfeature = { 
                "Additional details": details,
                "Read files": compreobj["file"]["read"],
                "TCP connections":compreobj["TCP connections"],
                "Hooking activity":compreobj["hooks"],
                "DNS requests":compreobj["DNS requests"],
                "HTTP requests":compreobj["HTTP requests"],
                "Opened services":compreobj["service"]["open"],
                "Written files": compreobj["file"]["modify"],
                "Deleted files": compreobj["file"]["delete"],
                "Created mutexes":compreobj["mutex"]["create"],
                "Searched windows":compreobj["searchedwindow"],
                "Opened files":compreobj["file"]["open"],
                "Replaced files":compreobj["file"]["create"],
                "Created processes":compreobj["processes"],
                "Opened mutexes":compreobj["mutex"]["open"],
                "UDP communications":compreobj["UDP connections"],
                "Runtime DLLs":compreobj["runtimedll"]
                } 

        try:
            reportname = compreobj["name"]+".json"
            path = os.path.join(self.vtfeature_path, reportname)
            with codecs.open(path, "w", "utf-8") as report:
                json.dump(vtfeature, report, sort_keys=True,
                          indent=int(indent), encoding=encoding)
        except (UnicodeError, TypeError, IOError) as e:
            raise CuckooReportError("Failed to generate JSON report: %s" % e)

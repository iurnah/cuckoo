#!/usr/bin/env python

import json
import os
import codecs

vtfeature_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'storage', 'vtfeature'))
dataset_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '..',
'storage', 'dataset'))

jsoncount = 0
dataset = []

for fname in os.listdir(vtfeature_path): 
    fpath = os.path.join(vtfeature_path, fname)
    jsoncount += 1
    with open(fpath) as fin:
        dataset.append(json.load(fin))

datasetname = "dataset-" + str(jsoncount)+ ".json" 

try:
    path = os.path.join(dataset_path, datasetname)
    with codecs.open(path, "w", "utf-8") as datareport:
        json.dump(dataset, datareport, sort_keys=False,
                indent=4, encoding="utf-8")
except:
    print "Failed to generate dataset.json"
else: 
    print "Done...\n {0} generated analysis json in {1} have been combined!".format(jsoncount, vtfeature_path)
    print "\nPlease find the combined dataset in {}".format(path)

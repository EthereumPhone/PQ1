# Copyright 2019 NXP
#
# SPDX-License-Identifier: Apache-2.0
#

import datetime
import os
import csv
import sys
import xml.etree.cElementTree as et
import xml.dom.minidom as dom

__VERSION__ = "2018.12.18_00"

#
#  Changelog:
#
#       2018.12.18_00 :  PGh  : Capture timestamps
#                     :       :
#       2018.12.14_00 :  PGh  : Added root suite name
#                     :       :
#       2018.08.02_00 :  PGh  : Add failure message as well
#                     :       :
#       2018.08.01_01 :  PGh  : Code Cleanup
#                     :       :
#       2018.08.01_00 :  CAy  : Initial implementaiton
#
#
# Todo:
#   - Handle case of appended results.
#   - Handle case of Ignore
#   - Handle case of Suites
#


DEBUG = True

def csv_to_unit_xml(root_name, in_csv, out_xml):
    csv_data = list()
    with open(in_csv) as csvfile:
        read_file = csv.reader(csvfile, delimiter = ',')
        for row in read_file:
            csv_data.append(row)

    if len(csv_data) == 0 or len(csv_data[0]) == 1:
        print("ERROR: Empty %s"%(in_csv))
        return

    fail_count=0
    for i in csv_data:
        if (i[5]=="FAILED"):
            fail_count=fail_count+1
    suite_name = csv_data[0][2]
    suite_start = int(csv_data[0][6])
    suite_end = int(csv_data[-1][7])

    if (suite_start == 0):
        timestamp = datetime.datetime.now().isoformat()
    else:
        timestamp = datetime.datetime.utcfromtimestamp(suite_start).isoformat()
    if root_name:
        testsuites = et.Element("testsuites",
            name="%s"%root_name,
            #id="0",
            tests="%d"%(len(csv_data)),
            errors="0",
            failures="%d"%fail_count,
            time="%ssec"%(1 + suite_end - suite_start),
            timstamp=timestamp)
        suite_name="%s.%s"%(root_name, suite_name)
        subsuites = et.SubElement(testsuites,
            "testsuite",
            name=suite_name,
            #id="0",
            tests="%d"%(len(csv_data)),
            errors="0",
            failures="%d"%fail_count,
            time="%ssec"%(1 + suite_end - suite_start),
            timstamp=timestamp )
    else:
        testsuites = et.Element("testsuites",
            name=suite_name,
            #id="0",
            tests="%d"%(len(csv_data)),
            errors="0",
            failures="%d"%fail_count,
            time="%ssec"%(1 + suite_end - suite_start),
            timstamp=timestamp)
        subsuites = testsuites

    all_ts = {}
    all_times = {}

    for i in csv_data:
        (file_name, line_number, test_suite, test_name, _, test_status, test_start, test_end, test_message) = i
        test_time = int(test_end) - int(test_start)
        if root_name:
            suite_name="%s.%s"%(root_name, test_suite)
        else:
            suite_name=test_suite

        if suite_name in all_times:
            all_times[suite_name] += test_time
        else:
            all_times[suite_name] = test_time

        if suite_name in all_ts:
            ts = all_ts[suite_name]
        else:
            ts = et.SubElement(subsuites,
                "testsuite",
                name=suite_name,
                #id="0",
                tests="%d"%(len(csv_data)),
                errors="0",
                failures="%d"%fail_count,
                time="%ssec"%(1 + int(test_end) - int(test_start)),
                timstamp=datetime.datetime.utcfromtimestamp(int(test_start)).isoformat())
            all_ts[suite_name] = ts

        tc = et.SubElement(ts,
            "testcase",
            classname=suite_name,
            name="%s"%test_name,
            status="%s"%test_status,
            time="%ssec"%(1 + int(test_end) - int(test_start)),
            timstamp=datetime.datetime.utcfromtimestamp(int(test_start)).isoformat())
        if (test_status=="FAILED"):
            et.SubElement(tc,"failure",message="%s"%file_name, type="FAILURE").text="Error %s in file %s in line %s"%(test_message, file_name,line_number)

    for k,v in all_times.items():
        all_ts[k].set("time","%ssec"%(1 + v,))

    tree = et.ElementTree(testsuites)
    tree.write(out_xml)
    if DEBUG:
        xml = dom.parse(out_xml)
        formatted_xml = xml.toprettyxml()
        f = open(out_xml,"w+")
        f.write("%s"%formatted_xml)
        f.close()

def usage(prog_name):
    print("%s [in:root_name] <in:csv> <out:junit_xml>"%(prog_name,))

def main():
    if len(sys.argv) == 3:
        csv_to_unit_xml(None, sys.argv[1],sys.argv[2])
    elif len(sys.argv) == 4:
        csv_to_unit_xml(sys.argv[1], sys.argv[2], sys.argv[3])
    else:
        if DEBUG:
            test(r'C:\temp\unity_in.csv', r'C:\temp\junit_out.xml')
        else:
            usage(sys.argv[0])

if __name__ == '__main__':
    main()

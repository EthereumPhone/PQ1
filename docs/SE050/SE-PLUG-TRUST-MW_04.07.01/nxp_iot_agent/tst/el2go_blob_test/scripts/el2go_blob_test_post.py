#!/usr/bin/env python3
# Copyright 2024 NXP
# SPDX-License-Identifier: Apache-2.0

import argparse
import pathlib
import re
import junitparser

parser = argparse.ArgumentParser(description='Converts el2go_blob_test console output to junit')

parser.add_argument('console_output_path', type=pathlib.Path, help='Path to the captured console output of el2go_blob_test')
parser.add_argument('junit_path', type=pathlib.Path, help='Path where the junit file should be written')

args = parser.parse_args()

if not args.console_output_path.is_file():
    parser.error("No file found at console_output_path")

console_output_file = open(args.console_output_path)
console_output = console_output_file.read()
cleaned_output = re.sub(r'\x1b\[[\d;]+m', '', console_output)

suites = []
current_suite = None
current_testcase = None
current_variation = None
current_stdout = []

for line in cleaned_output.splitlines():
    if current_suite is None:
        match = re.match("Running test suite (.*)", line)
        if match is not None:
            current_suite = junitparser.TestSuite(match.group(1))
        continue
    if current_testcase is None:
        match = re.match("> Executing test ([A-Z0-9_]*)", line)
        if match is not None:
            current_testcase = junitparser.TestCase(classname=match.group(1))
            continue
    if current_testcase is not None:
        match = re.match("  Description: '(.*)'", line)
        if match is not None:
            current_testcase.name = match.group(1).replace(" ", "_").upper()
            continue
        if current_variation is None:
            match = re.match("  > Executing variation ([A-Z0-9_]*)", line)
            if match is not None:
                if type(current_testcase) is not junitparser.TestSuite:
                    classname = current_testcase.classname
                    current_testcase = junitparser.TestSuite(current_testcase.name)
                    current_testcase.hostname = classname
                current_variation = junitparser.TestCase(classname=current_testcase.hostname)
                current_variation.name = match.group(1)
                continue
        if current_variation is not None:
            match = re.match("    Variation " + current_variation.name + " - ([A-Z]*) \(([0-9]*) ms\)", line)
            if match is not None:
                if match.group(1) == "FAILED":
                    info = current_stdout[0][4:]
                    stacktrace = current_stdout[1][4:]
                    current_variation.result = [junitparser.Failure(info)]
                    current_variation.system_err = stacktrace
                    current_variation.time = int(match.group(2)) / float(1000)
                else:
                    current_variation.time = int(match.group(2)) / float(1000)
                current_testcase.add_testcase(current_variation)
                current_stdout.clear()
                current_variation = None
                continue
        name = current_testcase.classname if type(current_testcase) is not junitparser.TestSuite else current_testcase.hostname
        match = re.match("  Test " + name + " - ([A-Z]*)(?: \(([0-9]*) ms\)|)", line)
        if match is not None:
            if type(current_testcase) is junitparser.TestSuite:
                current_testcase.hostname = current_suite.name.split(" (")[0]
                current_suite.add_testsuite(current_testcase)
            else:
                if match.group(1) == "SKIPPED":
                    info = current_stdout[0][2:]
                    current_testcase.result = [junitparser.Skipped(info)]
                elif match.group(1) == "FAILED":
                    info = current_stdout[0][2:]
                    stacktrace = current_stdout[1][2:]
                    current_testcase.result = [junitparser.Failure(info)]
                    current_testcase.system_err = stacktrace
                    current_testcase.time = int(match.group(2)) / float(1000)
                else:
                    current_testcase.time = int(match.group(2)) / float(1000)
                current_suite.add_testcase(current_testcase)
            current_stdout.clear()
            current_testcase = None
            continue
        current_stdout.append(line)
    if current_suite is not None:
        if "Test suite " + current_suite.name in line:
            current_suite.name = current_suite.name.split(" (")[0]
            suites.append(current_suite)
            current_suite = None
            continue

xml = junitparser.JUnitXml()
for suite in suites:
    xml.add_testsuite(suite)
    print(f"Successfully parsed test suite {suite.name} with {suite.tests} tests ({suite.failures} failed, {suite.skipped} skipped)")
xml.write(args.junit_path, pretty=True)

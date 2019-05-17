#!/usr/bin/env python2

#
# Copyright(c) 2012-2018 Intel Corporation
# SPDX-License-Identifier: BSD-3-Clause-Clear
#

import tests_config
import os
import commands
import sys

script_path = os.path.dirname(os.path.realpath(__file__))

main_UT_dir = os.path.normpath(script_path + os.sep\
	+ tests_config.MAIN_DIRECTORY_OF_UNIT_TESTS) + os.sep

main_tested_dir = os.path.normpath(script_path + os.sep\
	+ tests_config.MAIN_DIRECTORY_OF_TESTED_PROJECT) + os.sep


if not os.path.isdir(main_UT_dir + "ocf_env" + os.sep + "ocf"):
	try:
		os.makedirs(main_UT_dir + "ocf_env" + os.sep + "ocf")
	except Exception:
		print "Cannot create ocf_env/ocf directory!"

status, output = commands.getstatusoutput("cp " + main_tested_dir +\
	"inc" + os.sep + "*" + " " + main_UT_dir + "ocf_env" + os.sep + "ocf")


if os.system(script_path + os.sep + "prepare_sources_for_testing.py") != 0:
	print "Preparing sources for testing failed!"
	exit()


build_dir = main_UT_dir + "build" + os.sep
logs_dir = main_UT_dir + "logs" + os.sep

if not os.path.isdir(build_dir):
	try:
		os.makedirs(build_dir)
	except Exception:
		print "Cannot create build directory!"
if not os.path.isdir(logs_dir):
	try:
		os.makedirs(logs_dir)
	except Exception:
		print "Cannot create logs directory!"

cmake_status, cmake_output = commands.getstatusoutput("cd " + build_dir + " && cmake ..")
print cmake_output
with open(logs_dir + 'cmake.output', 'w') as f:
	f.write(cmake_output)

if cmake_status != 0:
	with open(logs_dir + 'tests.output', 'w') as f:
		f.write("Cmake step failed! More details in cmake.output.")
	sys.exit(1)

make_status, make_output = commands.getstatusoutput("cd " + build_dir + " && make")
print make_output
with open(logs_dir + 'make.output', 'w') as f:
	f.write(make_output)

if make_status != 0:
	with open(logs_dir + 'tests.output', 'w') as f:
		f.write("Make step failed! More details in make.output.")
	sys.exit(1)

test_status, test_output = commands.getstatusoutput("cd " + build_dir + " && make test")
print test_output
with open(logs_dir + 'tests.output', 'w') as f:
	f.write(test_output)

#!/usr/bin/env python2

#
# Copyright(c) 2012-2018 Intel Corporation
# SPDX-License-Identifier: BSD-3-Clause-Clear
#

import tests_config
import os
import commands

script_path = os.path.dirname(os.path.realpath(__file__))

main_UT_dir = os.path.normpath(script_path + os.sep\
	+ tests_config.MAIN_DIRECTORY_OF_UNIT_TESTS) + os.sep

main_tested_dir = os.path.normpath(script_path + os.sep\
	+ tests_config.MAIN_DIRECTORY_OF_TESTED_PROJECT) + os.sep


if not os.path.isdir(main_UT_dir + "ocf_env" + os.sep + "ocf"):
	try:
		os.makedirs(main_UT_dir + "ocf_env" + os.sep + "ocf")
	except Exception:
		print "Cannot crate ocf_env/ocf directory!"

status, output = commands.getstatusoutput("cp " + main_tested_dir +\
	"inc" + os.sep + "*" + " " + main_UT_dir + "ocf_env" + os.sep + "ocf")


if os.system(script_path + os.sep + "prepare_sources_for_testing.py") != 0:
	print "Preparing sources for testing failed!"
	exit()


build_dir = main_UT_dir + "build" + os.sep

if not os.path.isdir(build_dir):
	try:
		os.makedirs(build_dir)
	except Exception:
		print "Cannot crate build directory!"

status, output = commands.getstatusoutput("cd " + build_dir + " && cmake .. && make && make test")

print output

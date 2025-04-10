#!/bin/bash
#
# Copyright(c) 2023-2025 Huawei Technologies Co., Ltd.
# SPDX-License-Identifier: BSD-3-Clause
#

if [ $# -ne 1 ]; then
	echo "Missing arg, you must also send the 'name' you want to change to"
	exit 1
fi

ocf_sim=$1

if [ -f ../$ocf_sim ]; then
	echo "$ocf_sim exec already exists"
	exit 1
fi

if [ ! -x ../ocf_sim ]; then
	echo "The ocf_sim executable does not exist. Please compile the source code to generate it"
	exit 1
fi

if [[ ! $ocf_sim =~ ^us. ]];then
	echo "$ocf_sim : The name of a ocf_sim exec must start with the prefix 'us.'"
	exit 1
fi

LOGS_DIR=../logs

mv ../ocf_sim ../$ocf_sim
if [ ! -d $LOGS_DIR ]; then
	mkdir $LOGS_DIR;
fi

git diff > ${LOGS_DIR}/$ocf_sim.diff
git log --oneline -n 40 > ${LOGS_DIR}/$ocf_sim.git

echo "The name has been changed successfully"

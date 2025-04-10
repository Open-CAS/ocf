#!/bin/bash
#
# Copyright(c) 2023-2025 Huawei Technologies Co., Ltd.
# SPDX-License-Identifier: BSD-3-Clause
#

pat="$1"
print_head=0
for i in $(ls -1tr log.*${pat}*); do
	x=$i
	n=$(echo $x | cut -d\. -f 2 | cut -d- -f 1)
	# log.tpcc_32-64.us.leap.2.231001-120527 -> us.leap
	l=$(echo $x | sed -e 's/log\..*-[0-9]*\.u/u/g' -e 's/\.[0-9]*\.[0-9]*-[0-9]*$//g')
	c=$(echo $x | cut -d\. -f 2 | cut -d- -f 2)

	if [ $print_head -eq 0 ]; then
		echo "# log ver bench CSize RD_F_core PR_F_core WR_T_core RD_F_cache WR_T_cache PT_wr tot_RD sav_WR"
		print_head=1
	fi
	egrep "Reads from c|Prefetch from|Writes to c|Pass-Through writes" $i | grep '4KiB Blocks' |
		sed -e 's/(s)//g' -e 's/4KiB Blocks//g' -e 's/Pass-Through writes/PT_wr/g' -e 's/ stream//g' -e 's/://g' -e 's/ from /_F_/g' -e 's/ to /_T_/g' -e 's/  */ /g' -e 's/|[|]*//g'  -e 's/  */ /g' |
		tr -dc 'a-zA-Z0-9._\(\) \t\n' |
		paste - - - - - - | sed "s/^/ $x $l $n $c /" | awk '{print $1,$2,$3,$4,$6,$9,$12,$15,$18,$21}' |
		cat -n |
		awk '{print; printf "%d %d\n", $6+$7, $6+$8-$10}' |
		paste - -
done | column -t
#| sed 's/^1/\n1/'

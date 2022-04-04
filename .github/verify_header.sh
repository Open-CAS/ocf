#!/bin/bash

YEAR=$(date +"%Y")
REGEX="Copyright\(c\) [0-9]{4}-([0-9]{4})|Copyright\(c\) ([0-9]{4})"
FILE=$(cat $1)
while [[ ${FILE} =~ (${REGEX}) ]]; do
        echo ${BASH_REMATCH[1]}
        if [[ ${BASH_REMATCH[3]} != "" && $YEAR == ${BASH_REMATCH[3]} ]]
        then
            echo $1 have appropriate licence
            exit 0
        elif [[ ${BASH_REMATCH[2]} != "" && $YEAR == ${BASH_REMATCH[2]} ]]
        then
            echo $1 have appropriate licence
            exit 0
        fi
            FILE=${FILE#*$BASH_REMATCH}
done
echo $1 does not contain appropriate licence header
exit 1
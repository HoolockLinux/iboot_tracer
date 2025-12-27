#!/bin/sh

if [ "${OTOOL}" = "" ]; then
    OTOOL="otool"
fi

data=$("${OTOOL}" -d payload.macho | head -n5)

if [ "$data" != "payload.macho:" ]; then
    printf "Payload must only contain __TEXT!\n"
    #rm -f "$1"
    exit 1;
else
    exit 0
fi

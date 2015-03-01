#!/bin/sh

die () {
    echo ERROR: $*
    exit 1
}

: ${RTE_SDK:=$(pwd)/libs/dpdk}
: ${RTE_TARGET:=build}
export RTE_SDK
export RTE_TARGET

set -e
( cd libs/dpdk ; make T=$(uname -m)-native-linuxapp-gcc config && make || die dpdk build failed )
#( cd libs/mtcp/src && make || die mtcp build failed )

touch .build_done

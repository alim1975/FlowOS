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
( cd libs/dpdk; make T=$(uname -m)-native-linuxapp-gcc config && make || die dpdk build failed )
#( cd mtcp/src && make || die mtcp build failed )
#( cd libs/libcuckoo && autoreconf -fis && ./configure && make  || die libcuckoo build failed)

#( cd examples/pktcapture && make || die pktcapture build failed )
#( cd examples/mtcpclient && make || die mtcpclient build failed )
#( cd examples/echoserver && make || die echoserver build failed )

#( cd . && sed -i -e "s%libdir.*=.*'.*'%libdir=''%g" libs/libcuckoo/libcuckoo/libcityhash.la || die replace in libcityhash failed)

touch .build_done


#!/bin/sh

# source this file to get environment setup for the
# pyang below here

OPENCONFIG=$SR_CODE_BASE/external/src/openconfig/release
PYANGDIR=$SR_CODE_BASE/external/src/pyang
PWD=`pwd`

export PATH=$PATH:$PWD/bin:$PYANGDIR/bin
export MANPATH=$MANPATH:$PWD/man:$PYANGDIR/man
export PYTHONPATH=$PYTHONPATH:$PWD:$SR_CODE_BASE/external/src/pyang
export YANG_MODPATH=$PWD/modules:$OPENCONFIG/models/objects:$SR_CODE_BASE/snaproute/src/models/objects/yangmodel:$YANG_MODPATH
export PYANG_XSLT_DIR=$PWD/xslt
export PYANG_RNG_LIBDIR=$PWD/schema

export YANG_MODPATH=$PYANGDIR/modules:$YANG_MODPATH

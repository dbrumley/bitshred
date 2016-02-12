#!/bin/sh

mkdir bitshred_cc_hadoop-$1
mkdir bitshred_cc_hadoop-$1/bitshred_classes
cp AUTHORS INSTALL README ChangeLog CCGen.java CCInit.java CCRow.java CCCol.java gen_input.py make.sh run_cc.py bitshred_cc_hadoop-$1
tar czf bitshred_cc_hadoop-$1.tar.gz bitshred_cc_hadoop-$1
rm -rf bitshred_cc_hadoop-$1

#!/bin/sh

mkdir bitshred_hadoop-$1
cp AUTHORS INSTALL README ChangeLog Cmp.java Gen.java input.py make.sh run_gen.sh run_cmp.sh bitshred_hadoop-$1
tar czf bitshred_hadoop-$1.tar.gz bitshred_hadoop-$1
rm -rf bitshred_hadoop-$1

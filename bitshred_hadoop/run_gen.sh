#!/bin/sh

hadoop dfs -rmr /user/jiyongj/output-gen
hadoop jar BitShred.jar Gen /user/jiyongj/input-gen /user/jiyongj/output-gen

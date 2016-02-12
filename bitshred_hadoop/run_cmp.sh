#!/bin/sh

hadoop dfs -rmr /user/jiyongj/output-cmp
hadoop jar BitShred.jar Cmp /user/jiyongj/input-cmp /user/jiyongj/output-cmp

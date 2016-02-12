#!/bin/sh

hadoop dfs -rmr /user/jiyongj/output-info
hadoop jar Info.jar Info /user/jiyongj/input-info /user/jiyongj/output-info

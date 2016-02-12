#!/bin/sh

javac -classpath ${HADOOP_HOME}/hadoop-*-core.jar -d bitshred_classes Gen.java
javac -classpath ${HADOOP_HOME}/hadoop-*-core.jar -d bitshred_classes Cmp.java
jar -cvf ./BitShred.jar -C bitshred_classes/ .

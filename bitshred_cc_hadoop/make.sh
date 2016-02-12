#!/bin/sh

javac -classpath ${HADOOP_HOME}/hadoop-*-core.jar -Xlint:deprecation -d bitshred_classes CCGen.java
javac -classpath ${HADOOP_HOME}/hadoop-*-core.jar -Xlint:deprecation -d bitshred_classes CCInit.java
javac -classpath ${HADOOP_HOME}/hadoop-*-core.jar -Xlint:deprecation -d bitshred_classes CCRow.java
javac -classpath ${HADOOP_HOME}/hadoop-*-core.jar -Xlint:deprecation -d bitshred_classes CCCol.java
jar -cvf ./CC.jar -C bitshred_classes/ .

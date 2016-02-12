#!/bin/sh

javac -cp prefuse.jar -d clustermap_classes/ ClusterMap.java
jar -cvf ./ClusterMap.jar -C clustermap_classes/ .
#java -Xms32m -Xmx1024m -cp prefuse.jar:ClusterMap.jar ClusterMap

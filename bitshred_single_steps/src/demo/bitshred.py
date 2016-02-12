#!/usr/bin/python

import sys
import os

def cdb_tree(threshold):
    treeout = open('cdb_tree.xml', 'w')
    vlist = open('db/vdb_list', 'r')
    vlistlines = vlist.readlines()
    cdb = open('db/cdb_%03d' % int(threshold*100), 'r')

    treeout.write('<tree>\n')
    treeout.write('  <declarations>\n')
    treeout.write('    <attributeDecl name=\"name\" type=\"String\"/>\n')
    treeout.write('    <attributeDecl name=\"vlabel\" type=\"String\"/>\n')
    treeout.write('  </declarations>\n')
    treeout.write('  <branch>\n')
    treeout.write('    <attribute name=\"name\" value=\"Categories\"/>\n')

    for line in cdb:
        cid = int(line.split(':')[0])
        clist = (line.split(':')[1]).split()
        csize = int(line.split(':')[2])
        treeout.write('    <branch>\n')
        treeout.write('      <attribute name=\"name\" value=\"C%s\"/>\n' % cid)
        for i in range(0, csize):
            vid = int(clist[i])
            vname = ((vlistlines[vid-1].split(':')[1])).split('/')[-1]
            vlabel = vlistlines[vid-1].split(':')[4]
            treeout.write('      <leaf>\n')
            treeout.write('        <attribute name=\"name\" value=\"%s\"/>\n' % vname)
            treeout.write('        <attribute name=\"vlabel\" value=\"%s\"/>\n' % vlabel)
            treeout.write('      </leaf>\n')
        treeout.write('    </branch>\n')
    treeout.write('  </branch>\n')
    treeout.write('</tree>\n')

    treeout.close()
    vlist.close()
    cdb.close()


if len(sys.argv) != 4:
    print sys.argv[0] + " <log_file>  <# of samples>  <threshold>"
    sys.exit(-1)

prog = "../bitshred"
threshold = float(sys.argv[3])

if sys.argv[1]=='-':
    os.system('%s -r -t %f' % (prog, threshold))
    cdb_tree(threshold)
    os.system('java -Xms32m -Xmx1024m -cp clustermap/prefuse.jar:clustermap/ClusterMap.jar ClusterMap')
else:
    log = sys.argv[1]
    limit = sys.argv[2] 
    size = 16
    w = 12

    os.system('%s -u %s -s %d -w %d -l %s' % (prog, log, size, w, limit))
    os.system('%s -p' % prog)
    os.system('%s -r -t %f' % (prog, threshold))
    cdb_tree(threshold)
    os.system('java -Xms32m -Xmx1024m -cp clustermap/prefuse.jar:clustermap/ClusterMap.jar ClusterMap')

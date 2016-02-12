#!/usr/bin/python
#
# quality.py
#  : measure clustering precision / recall
#
#  - Jiyong Jang (2012)
#

import sys
import os

def precision(ref_lines, cdb_lines):
    tp = 0
    t_num = 0

    for cline in cdb_lines:
        clist = (cline.split(':')[1]).split()
        clist_num = len(clist)
        t_num += clist_num
        maxcnt = 0
        for rline in ref_lines:
            rlist = (rline.split(':')[1]).split()
            rlist_num = len(rlist)
            cnt = 0
            for v in clist:
                if v in rlist:
                    cnt += 1
            if cnt > maxcnt:
                maxcnt = cnt
                if maxcnt == clist_num:
                    break
        tp += maxcnt

    print '[-] precision:\t%.5f\t(%d/%d)' % (float(tp)/t_num, tp, t_num)

def recall(ref_lines, cdb_lines):
    tp = 0
    t_num = 0

    for rline in ref_lines:
        rlist = (rline.split(':')[1]).split()
        rlist_num = len(rlist)
        t_num += rlist_num
        maxcnt = 0
        for cline in cdb_lines:
            clist = (cline.split(':')[1]).split()
            clist_num = len(clist)
            cnt = 0
            for v in rlist:
                if v in clist:
                    cnt += 1
            if cnt > maxcnt:
                maxcnt = cnt
                if maxcnt == rlist_num:
                    break
        tp += maxcnt

    print '[-] recall:\t%.5f\t(%d/%d)' % (float(tp)/t_num, tp, t_num)


if len(sys.argv) != 3:
    print sys.argv[0] + " <ref_path> <cdb_path>"
    sys.exit(-1)

ref = open(sys.argv[1], 'r')
cdb = open(sys.argv[2], 'r')

ref_lines = ref.readlines()
cdb_lines = cdb.readlines()

precision(ref_lines, cdb_lines)
recall(ref_lines, cdb_lines)

ref.close()
cdb.close()

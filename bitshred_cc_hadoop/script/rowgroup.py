#!/usr/bin/python
import os
import sys
from collections import defaultdict

d = defaultdict(list)

f = open(sys.argv[1], 'r')
fin = open('cc-single', 'r').readlines()
fout = open('rgroup.log', 'w')
fout2 = open('rgroup_name.log', 'w')
rlist = (f.readline()).split(',')

samplenumber = 0
for r in rlist:
    rgroup = int(r)
    d[rgroup].append(samplenumber)
    samplenumber += 1

for i in d.keys():
    fout.write('%d:' % i)
    fout2.write('%d:\n' % i)
    cnt = 0
    for j in d[i]:
        fout.write('%d ' % j)
        fout2.write('%d\t%s\n' % (j, fin[j].split(':')[1]))
        cnt += 1
    fout.write(':%d:\n' % cnt)
    fout2.write('\n')
fout.close()
fout2.close()
f.close()

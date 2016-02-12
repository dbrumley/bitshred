#!/usr/bin/python
import sys
import os

if len(sys.argv) != 2:
    print sys.argv[0] + " numBlocks"
    sys.exit(-1)

numBlocks = int(sys.argv[1])

## input_cmp
if os.path.exists("./input-cmp") == True:
    os.system("rm -rf ./input-cmp")
os.mkdir("./input-cmp")

counter = 0

for i in range(0, numBlocks, 2):
    foutpath = "./input-cmp/%d" % counter
    fout = open(foutpath, "w")
    fout.write("%d\t%d\n" % (i, i))
    fout.write("%d\t%d\n" % (i+1, i+1))
    fout.close()
    counter += 1

for i in range(0, numBlocks):
    for j in range(i+1, numBlocks):
        foutpath = "./input-cmp/%d" % counter
        fout = open(foutpath, "w")
        fout.write("%d\t%d\n" % (i, j))
        fout.close()
        counter += 1

print counter

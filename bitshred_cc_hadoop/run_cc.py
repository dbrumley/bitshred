#!/usr/bin/python

import sys
import os

if len(sys.argv) != 4:
    print sys.argv[0] + " <numSamples>  <numRowGroups>  <numColGroups>"
    print ""
    print " *numSamples  : total number of malware samples"
    print " *numRowGroups: initial number of row groups"
    print " *numColGroups: initial number of column groups"
    sys.exit(-1)

## log file
outlog = open('result.log', 'w')

## parameters
numSamples = int(sys.argv[1])
numRowGroups = int(sys.argv[2])
numColGroups = int(sys.argv[3])

## Running CCGen
os.system('hadoop dfs -rmr /user/jiyongj/cc/adjlist/*')
os.system('hadoop dfs -rmr /user/jiyongj/cc/output-ccgen')
os.system('hadoop jar CC.jar CCGen /user/jiyongj/cc/input-ccgen /user/jiyongj/cc/output-ccgen')

os.system('hadoop dfs -rmr /user/jiyongj/cc/global/*')

rowGroupsIncrease = True
colGroupsIncrease = False
rowStop = False
colStop = False
numGroupIter = 0
while 1:
    numGroupIter += 1

    ## Running CCInit
    os.system('hadoop dfs -rmr /user/jiyongj/cc/output-ccinit')
    os.system('hadoop jar CC.jar CCInit %d %d %d /user/jiyongj/cc/input-ccinit /user/jiyongj/cc/output-ccinit' % (numSamples, numRowGroups, numColGroups))
    os.system('hadoop dfs -rm /user/jiyongj/cc/global/g_%d_%d_0' % (numRowGroups, numColGroups))
    os.system('hadoop dfs -mv /user/jiyongj/cc/output-ccinit/part-r-00000 /user/jiyongj/cc/global/g_%d_%d_0' % (numRowGroups, numColGroups))

    numIter = 0
    while 1:
        numIter += 1
        
        ## Running CCRow
        os.system('hadoop dfs -rmr /user/jiyongj/cc/output-ccrow')
        os.system('hadoop jar CC.jar CCRow %d %d %d %d /user/jiyongj/cc/input-ccrow /user/jiyongj/cc/output-ccrow' % (numSamples, numRowGroups, numColGroups, numIter))
        os.system('hadoop dfs -rm /user/jiyongj/cc/global/g_%d_%d_%d_row' % (numRowGroups, numColGroups, numIter))
        os.system('hadoop dfs -mv /user/jiyongj/cc/output-ccrow/part-r-00000 /user/jiyongj/cc/global/g_%d_%d_%d_row' % (numRowGroups, numColGroups, numIter))

        ## Running CCCol
        os.system('hadoop dfs -rmr /user/jiyongj/cc/output-cccol')
        os.system('hadoop jar CC.jar CCCol %d %d %d %d /user/jiyongj/cc/input-cccol /user/jiyongj/cc/output-cccol' % (numSamples, numRowGroups, numColGroups, numIter))
        os.system('hadoop dfs -rm /user/jiyongj/cc/global/g_%d_%d_%d' % (numRowGroups, numColGroups, numIter))
        os.system('hadoop dfs -mv /user/jiyongj/cc/output-cccol/part-r-00000 /user/jiyongj/cc/global/g_%d_%d_%d' % (numRowGroups, numColGroups, numIter))

        if numIter==1:
            prevCost = float(os.popen('hadoop dfs -cat /user/jiyongj/cc/global/cost_%d_%d_%d' % (numRowGroups, numColGroups, numIter)).read())
            curRowGroups = float(os.popen('hadoop dfs -cat /user/jiyongj/cc/global/rnum_%d_%d_%d' % (numRowGroups, numColGroups, numIter)).read())
            curColGroups = float(os.popen('hadoop dfs -cat /user/jiyongj/cc/global/cnum_%d_%d_%d' % (numRowGroups, numColGroups, numIter)).read())
            outlog.write('[-] %d (%d) RowGroups, %d (%d) ColGroups: %.2f at %d iteration\n' % (numRowGroups, curRowGroups, numColGroups, curColGroups, prevCost, numIter))
            outlog.flush()
            continue
        else:
            curCost = float(os.popen('hadoop dfs -cat /user/jiyongj/cc/global/cost_%d_%d_%d' % (numRowGroups, numColGroups, numIter)).read())
            curRowGroups = float(os.popen('hadoop dfs -cat /user/jiyongj/cc/global/rnum_%d_%d_%d' % (numRowGroups, numColGroups, numIter)).read())
            curColGroups = float(os.popen('hadoop dfs -cat /user/jiyongj/cc/global/cnum_%d_%d_%d' % (numRowGroups, numColGroups, numIter)).read())
            outlog.write('[-] %d (%d) RowGroups, %d (%d) ColGroups: %.2f at %d iteration\n' % (numRowGroups, curRowGroups, numColGroups, curColGroups, curCost, numIter))
            outlog.flush()
            
            ## If current cost does not decrease that much, it stops.
            if curCost < prevCost*0.999:
                prevCost = curCost
            else:
                break

    ## After changing the number of row/column groups, it runs again to find the optimal value.
    ## The changing difference can be adapted to a data set.
    if numGroupIter==1:
        prevGroupCost = prevCost
        numRowGroups += 8
        continue
    else:
        curGroupCost = prevCost
        if curGroupCost>=prevGroupCost:
            if rowGroupsIncrease==True:
                numRowGroups -= 8
                rowStop=True
                if colStop==True:
                    break
                else:
                    rowGroupsIncrease=False
                    numColGroups *= 2
            else:
                numColGroups /= 2
                colStop=True
                if rowStop==True:
                    break
                else:
                    rowGroupsIncrease=True
                    numRowGroups += 8
                
        elif curGroupCost < prevGroupCost:
            prevGroupCost = curGroupCost
            if rowGroupsIncrease==True:
                numRowGroups += 8
                colStop=False
            else:
                numColGroups *= 2
                rowStop=False
                
outlog.close()

## At the end, global values (r,c,G), adjacent lists (fingerprints), and a result log are in a current folder.
os.system('hadoop dfs -get /user/jiyongj/cc/global .')
os.system('hadoop dfs -get /user/jiyongj/cc/adjlist .')

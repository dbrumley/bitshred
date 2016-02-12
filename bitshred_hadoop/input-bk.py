#!/usr/bin/python
import sys
import os

if len(sys.argv) != 5:
    print sys.argv[0] + " <logfile>  <numSamples>  <samplesPerFile>  <taskMultiply>"
    sys.exit(-1)

logfile = sys.argv[1]
numSamples = int(sys.argv[2])
samplesPerFile = int(sys.argv[3])
#maxMapTask = int(sys.argv[4])
taskMultiply = int(sys.argv[4])

## input_gen
if os.path.exists("./input-gen") == True:
    os.system("rm -rf ./input-gen")
os.mkdir("./input-gen")

fin = open(logfile, "r")
lines = fin.readlines()
sampleIndex = 0
numInputFiles = numSamples/samplesPerFile

for i in range(0, numInputFiles):
    foutpath = "./input-gen/%d" %i
    fout = open(foutpath, "w")
    for j in range(0, samplesPerFile):
        sampleIndex += 1
        fout.write("%d\t%s\n" % (sampleIndex, lines[sampleIndex-1].split(':')[0]))
    fout.close()
fin.close()

#numTasksPerNode = numSamples/maxMapTask
#remTasks = numSamples - (numSamples/maxMapTask)*maxMapTask
#sampleIndex = 0
#fin = open(logfile, "r")
#lines = fin.readlines()
#
#for i in range(0, maxMapTask):
#    foutpath = "./input-gen/%d" % i
#    fout = open(foutpath, "w")
#    if i < remTasks:
#        numTasks = numTasksPerNode+1
#    else:
#        numTasks = numTasksPerNode
#    for j in range(0, numTasks):
#        sampleIndex += 1
#        fout.write("%d\t%s\n" % (sampleIndex, lines[sampleIndex-1].split(':')[0]))
#    fout.close()
#fin.close()


## input_cmp
if os.path.exists("./input-cmp") == True:
    os.system("rm -rf ./input-cmp")
os.mkdir("./input-cmp")

numFiles = numSamples/samplesPerFile

if (taskMultiply == 4):
    cutWidth = numFiles/8;
    cutIndex1 = cutWidth;
    cutIndex2 = (cutWidth*2)
    cutIndex3 = (cutWidth*3)
    cutIndex4 = (cutWidth*4)
    cutIndex5 = (cutWidth*5)
    cutIndex6 = (cutWidth*6)
    cutIndex7 = (cutWidth*7)

    fileNumber = 0

    for idV in range(0, cutIndex4):
        foutpath = "./input-cmp/%d" % fileNumber
        fout = open(foutpath, "w")
        for idH in range(cutIndex4, cutIndex5):
            fout.write("%d\t%d\n" % (idV, idH))
        fout.close()
        fileNumber += 1

    for idV in range(0, cutIndex4):
        foutpath = "./input-cmp/%d" % fileNumber
        fout = open(foutpath, "w")
        for idH in range(cutIndex5, cutIndex6):
            fout.write("%d\t%d\n" % (idV, idH))
        fout.close()
        fileNumber += 1

    for idV in range(0, cutIndex4):
        foutpath = "./input-cmp/%d" % fileNumber
        fout = open(foutpath, "w")
        for idH in range(cutIndex6, cutIndex7):
            fout.write("%d\t%d\n" % (idV, idH))
        fout.close()
        fileNumber += 1

    for idV in range(0, cutIndex4):
        foutpath = "./input-cmp/%d" % fileNumber
        fout = open(foutpath, "w")
        for idH in range(cutIndex7, numFiles):
            fout.write("%d\t%d\n" % (idV, idH))
        fout.close()
        fileNumber += 1

    for idV in range(cutIndex4, cutIndex6):
        foutpath = "./input-cmp/%d" % fileNumber
        fout = open(foutpath, "w")
        for idH in range(cutIndex6, cutIndex7):
            fout.write("%d\t%d\n" % (idV, idH))
        fout.close()
        fileNumber += 1

    for idV in range(cutIndex4, cutIndex6):
        foutpath = "./input-cmp/%d" % fileNumber
        fout = open(foutpath, "w")
        for idH in range(cutIndex7, numFiles):
            fout.write("%d\t%d\n" % (idV, idH))
        fout.close()
        fileNumber += 1

    for idV in range(0, cutIndex2):
        foutpath = "./input-cmp/%d" % fileNumber
        fout = open(foutpath, "w")
        for idH in range(cutIndex2, cutIndex3):
            fout.write("%d\t%d\n" % (idV, idH))
        fout.close()
        fileNumber += 1

    for idV in range(0, cutIndex2):
        foutpath = "./input-cmp/%d" % fileNumber
        fout = open(foutpath, "w")
        for idH in range(cutIndex3, cutIndex4):
            fout.write("%d\t%d\n" % (idV, idH))
        fout.close()
        fileNumber += 1

    offset = 1 
    for idV in range(cutIndex4, cutIndex5):
        foutpath = "./input-cmp/%d" % fileNumber
        fout = open(foutpath, "w")
        for idH in range(idV, cutIndex5):
            fout.write("%d\t%d\n" % (idV, idH))
        t_idV = idV-offset
        for idH in range(t_idV, cutIndex4):
            fout.write("%d\t%d\n" % (t_idV, idH))
        fout.close()
        offset += 2
        fileNumber += 1

    offset = (cutWidth*2)+1
    for idV in range(cutIndex5, cutIndex6):
        foutpath = "./input-cmp/%d" % fileNumber
        fout = open(foutpath, "w")
        for idH in range(idV, cutIndex6):
            fout.write("%d\t%d\n" % (idV, idH))
        t_idV = idV-offset
        for idH in range(t_idV, cutIndex3):
            fout.write("%d\t%d\n" % (t_idV, idH))
        fout.close()
        offset += 2
        fileNumber += 1

    offset = (cutWidth*4)+1
    for idV in range(cutIndex6, cutIndex7):
        foutpath = "./input-cmp/%d" % fileNumber
        fout = open(foutpath, "w")
        for idH in range(idV, cutIndex7):
            fout.write("%d\t%d\n" % (idV, idH))
        t_idV = idV-offset
        for idH in range(t_idV, cutIndex2):
            fout.write("%d\t%d\n" % (t_idV, idH))
        fout.close()
        offset += 2
        fileNumber += 1

    offset = (cutWidth*6)+1
    for idV in range(cutIndex7, numFiles):
        foutpath = "./input-cmp/%d" % fileNumber
        fout = open(foutpath, "w")
        for idH in range(idV, numFiles):
            fout.write("%d\t%d\n" % (idV, idH))
        t_idV = idV-offset
        for idH in range(t_idV, cutIndex1):
            fout.write("%d\t%d\n" % (t_idV, idH))
        fout.close()
        offset += 2
        fileNumber += 1

    for idV in range(0, cutIndex1):
        foutpath = "./input-cmp/%d" % fileNumber
        fout = open(foutpath, "w")
        for idH in range(cutIndex1, cutIndex2):
            fout.write("%d\t%d\n" % (idV, idH))
        fout.close()
        fileNumber += 1

    for idV in range(cutIndex2, cutIndex3):
        foutpath = "./input-cmp/%d" % fileNumber
        fout = open(foutpath, "w")
        for idH in range(cutIndex3, cutIndex4):
            fout.write("%d\t%d\n" % (idV, idH))
        fout.close()
        fileNumber += 1

    for idV in range(cutIndex4, cutIndex5):
        foutpath = "./input-cmp/%d" % fileNumber
        fout = open(foutpath, "w")
        for idH in range(cutIndex5, cutIndex6):
            fout.write("%d\t%d\n" % (idV, idH))
        fout.close()
        fileNumber += 1

    for idV in range(cutIndex6, cutIndex7):
        foutpath = "./input-cmp/%d" % fileNumber
        fout = open(foutpath, "w")
        for idH in range(cutIndex7, numFiles):
            fout.write("%d\t%d\n" % (idV, idH))
        fout.close()
        fileNumber += 1
    
    print fileNumber

### taskMultiply = 2
elif (taskMultiply == 2):
    cutWidth = numFiles/4;
    cutIndex1 = cutWidth;
    cutIndex2 = (cutWidth*2)
    cutIndex3 = (cutWidth*3)

    fileNumber = 0

    for idV in range(0, cutIndex1):
        foutpath = "./input-cmp/%d" % fileNumber
        fout = open(foutpath, "w")
        for idH in range(cutIndex1, cutIndex2):
            fout.write("%d\t%d\n" % (idV, idH))
        fout.close()
        fileNumber += 1

    for idV in range(0, cutIndex2):
        foutpath = "./input-cmp/%d" % fileNumber
        fout = open(foutpath, "w")
        for idH in range(cutIndex2, cutIndex3):
            fout.write("%d\t%d\n" % (idV, idH))
        fout.close()
        fileNumber += 1

    offset = 1
    for idV in range(cutIndex2, cutIndex3):
        foutpath = "./input-cmp/%d" % fileNumber
        fout = open(foutpath, "w")
        for idH in range(idV, cutIndex3):
            fout.write("%d\t%d\n" % (idV, idH))
        t_idV = idV-offset
        for idH in range(t_idV, cutIndex2):
            fout.write("%d\t%d\n" % (t_idV, idH))
        fout.close()
        offset += 2
        fileNumber += 1

    for idV in range(0, cutIndex2):
        foutpath = "./input-cmp/%d" % fileNumber
        fout = open(foutpath, "w")
        for idH in range(cutIndex3, numFiles):
            fout.write("%d\t%d\n" % (idV, idH))
        fout.close()
        fileNumber += 1

    for idV in range(cutIndex2, cutIndex3):
        foutpath = "./input-cmp/%d" % fileNumber
        fout = open(foutpath, "w")
        for idH in range(cutIndex3, numFiles):
            fout.write("%d\t%d\n" % (idV, idH))
        fout.close()
        fileNumber += 1

    offset = (cutWidth*2)+1
    for idV in range(cutIndex3, numFiles):
        foutpath = "./input-cmp/%d" % fileNumber
        fout = open(foutpath, "w")
        for idH in range(idV, numFiles):
            fout.write("%d\t%d\n" % (idV, idH))
        t_idV = idV-offset
        for idH in range(t_idV, cutIndex1):
            fout.write("%d\t%d\n" % (t_idV, idH))
        fout.close()
        offset += 2
        fileNumber += 1

    print fileNumber



## Row Split
#
#numFiles = numSamples/samplesPerFile
#
#if numFiles%(maxMapTask*2) == 0:
#    temp = numFiles
#else:
#    temp = ((numFiles/(maxMapTask*2))+1)*(maxMapTask*2)
#
#print "%d - %d" % ((temp)-(maxMapTask*2), temp)
#
#numRowTasksPerMap = (temp/2)/maxMapTask
#numRows = maxMapTask*2
#
#for i in range(0, maxMapTask):
#    foutpath = "./input-cmp/%d" % i
#    fout = open(foutpath, "w")
#    startRowIndex = i
#    for j in range(0, numRowTasksPerMap):
#        element = (startRowIndex*numRowTasksPerMap) + j
#        if element<=numFiles:
#            fout.write("%d\n" % element)
#    startRowIndex = (numFiles-1)-i
#    for j in range(0, numRowTasksPerMap):
#        element = (startRowIndex*numRowTasksPerMap) + j
#        if element<=numFiles:
#            fout.write("%d\n" % element)
#    fout.close()


#if numSamples%(maxMapTask*2) == 0:
#    temp = numSamples+1
#else:
#    temp = ((numSamples/(maxMapTask*2))+1)*(maxMapTask*2)+1
#
#print "%d - %d" % ((temp-1)-(maxMapTask*2), (temp-1))
#
#numTasksInBlock = ((temp-1)/2)/maxMapTask
#numBlocks = maxMapTask*2
#
#for i in range(0, maxMapTask):
#    foutpath = "./input-cmp/%d" % i
#    fout = open(foutpath, "w")
#    startBlockIndex = i
#    for j in range(1, numTasksInBlock+1):
#        element = (startBlockIndex*numTasksInBlock) + j
#        if element<=numSamples:
#            fout.write("%d\n" % element)
#    startBlockIndex = (numBlocks-1)-i
#    for j in range(1, numTasksInBlock+1):
#        element = (startBlockIndex*numTasksInBlock) + j
#        if element<=numSamples:
#            fout.write("%d\n" % element)
#    fout.close()

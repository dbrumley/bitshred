#!/usr/bin/python
import sys
import os

if len(sys.argv) != 4:
    print sys.argv[0] + " <logfile>  <numSamples>  <samplesPerFile>"
    print ""
    print " *logfile:        log file containing the list of malware samples'"
    print "                  (ex) \'sample000/5870b9a54e906eeb45b98405b9ed9bb5\'"
    print " *numSamples:     total number of malware samples"
    print " *samplesPerFile: number of fingerprints to be stored per file"
    sys.exit(-1)

logfile = sys.argv[1]
numSamples = int(sys.argv[2])     # number of samples
samplesPerFile = int(sys.argv[3]) # number of samples (fingerprints) to be stored per file
fpSize = 1024*32                  # fingerpint size

## Create input_ccgen
if os.path.exists("input-ccgen") == True:
    os.system("rm -rf input-ccgen")
os.mkdir("input-ccgen")

fin = open(logfile, "r")
lines = fin.readlines()
sampleIndex = 1
numInputFiles = numSamples/samplesPerFile

for i in range(0, numInputFiles):
    foutpath = "input-ccgen/%d" %i
    fout = open(foutpath, "w")
    for j in range(0, samplesPerFile):
        fout.write("%d\t%s\n" % (sampleIndex, (lines[sampleIndex-1])[:-1]))
        sampleIndex += 1
    fout.close()
fin.close()
print "[-] CCGen utilizes %d map tasks." % numInputFiles

## Create input_ccinit
if os.path.exists("input-ccinit") == True:
    os.system("rm -rf input-ccinit")
os.mkdir("input-ccinit")

for i in range(0, numInputFiles):
    inrow = open('input-ccinit/%d' % i, 'w')
    inrow.write('%d' % i)
    inrow.close()
print "[-] CCInit utilizes %d map tasks." % numInputFiles

## Create input_ccrow
if os.path.exists("input-ccrow") == True:
    os.system("rm -rf input-ccrow")
os.mkdir("input-ccrow")

for i in range(0, numInputFiles):
    inrow = open('input-ccrow/%d' % i, 'w')
    inrow.write('%d' % i)
    inrow.close()
print "[-] CCRow utilizes %d map tasks." % numInputFiles

## Create input_cccol
## 1,2,...,FP_SIZE*8/chunkSize
chunkSize = 4096
if os.path.exists("input-cccol") == True:
    os.system("rm -rf input-cccol")
os.mkdir("input-cccol")

for i in range(0,(fpSize*8/chunkSize)):
    incol = open('input-cccol/%d' % i, 'w')
    incol.write('%d' % i)
    incol.close()
print "[-] CCCol utilizes %d map tasks." % (fpSize*8/chunkSize)

#!/usr/bin/env python

import sys

samplepath = ""

def main():
    for line in sys.stdin:
        line = line.strip()
        fn1, fn2 = line.split(':')
        fp1 = os.path.join(samplepath, fn1)
        fp2 = os.path.join(samplepath, fn2)
        f1 = open(fp1, "rb")
        f2 = open(fp2, "rb")
        bf1 = f1.readline()
        bf2 = f2.readline()


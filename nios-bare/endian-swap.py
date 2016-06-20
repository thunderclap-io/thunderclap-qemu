#!/usr/bin/env python

import sys

lines = sys.stdin.readlines();
for i in range(0,len(lines)):
    print lines[len(lines)-i-1].rstrip('\n')


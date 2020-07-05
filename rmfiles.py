#!/usr/bin/env python3

import subprocess
import sys
import os

if os.geteuid() != 0:
   exit('You must be root')

files = []
with open(sys.argv[1], 'r') as f:
    files = filter(None, f.read().split('\n'))

for f in files:
    answer = input("Remove file '" + f + "'? [Y/n] ").lower()
    if answer != 'n':
        subprocess.call(['rm', f])

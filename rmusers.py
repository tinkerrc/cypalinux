#!/usr/bin/env python3

import os
import subprocess
import sys

if os.geteuid() != 0:
   exit('You must be root')

authed = []
with open(sys.argv[1], "r") as f:
   authed = filter(None, f.read().split(sep='\n'))

unchecked = []
with open(sys.argv[2], "r") as f:
   unchecked = filter(None, f.read().split(sep='\n'))

with open(sys.argv[3], "w") as f:
   for user in unchecked:
      if user not in authed:
         answer = input("Found unauthorized user " + user + ", remove? [y/N] ").lower()
         if answer == 'y':
            subprocess.run(['deluser', "-r", user])
      pw = sys.argv[4]
      subprocess.run(['usermod', '-p', pw, user])

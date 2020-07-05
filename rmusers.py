#!/usr/bin/env python3

import os
import subprocess
import sys

if os.geteuid() != 0:
   exit('You must be root')

auth_file = sys.argv[1]
unchecked_file = sys.argv[2]
unauthed_file = sys.argv[3]
pw = sys.argv[4]


authed = []
with open(auth_file, "r") as f:
   authed = list(filter(None, f.read().split(sep='\n')))

unchecked = []
with open(unchecked_file, "r") as f:
   unchecked = list(filter(None, f.read().split(sep='\n')))

with open(unauthed_file, "w") as f:
   for user in unchecked:
      if user not in authed:
         answer = input("Found unauthorized user " + user + ", remove? [y/N] ").lower()
         if answer == 'y':
            subprocess.call(['deluser', "-r", user])
            f.write(user + "\n")
      subprocess.call(['usermod', '-p', pw, user])

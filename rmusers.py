#!/usr/bin/env python3

import os
import subprocess
import sys
from pwd import getpwnam

if os.geteuid() != 0:
    sys.exit('You must be root')

auth_file = sys.argv[1]
unchecked_file = sys.argv[2]
unauthed_file = sys.argv[3]

authed = []
with open(auth_file, "r") as f:
    authed = list(filter(None, f.read().split(sep='\n')))

unchecked = []
with open(unchecked_file, "r") as f:
    unchecked = list(filter(None, f.read().split(sep='\n')))

with open(unauthed_file, "w") as f:
    for user in unchecked:
        if user not in authed:
            uid = str(getpwnam(user).pw_uid)
            answer = input("Found unauthorized user " + user
                           + " with UID " + uid +
                           ", remove? [y/N] ").lower()
            if answer == 'y':
                subprocess.call(['deluser', "--remove-home", user])
                f.write(user + "\n")
                print("User '" + user + "' (" + uid + ") removed")
                continue
            else:
                print("User '" + user + "' (" + uid + ") not removed")
        subprocess.call(['chage', '--maxdays', '90', user])
        subprocess.call(['chage', '--mindays', '7', user])
        subprocess.call(['chage', '--warndays', '7', user])

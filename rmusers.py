#!/usr/bin/env python3

import os
import subprocess
import sys
from pwd import getpwnam

if os.geteuid() != 0:
    sys.exit('You must be root')

data_dir = sys.argv[1]
auth_file = os.path.join(data_dir, "auth")
unchecked_file = os.path.join(data_dir, "check")
unauthed_file = os.path.join(data_dir, "unauth")

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
            print("User '" + user + "' (" + uid + ") not removed")
        subprocess.call(['chage', '-M15', '-m6', '-W7', '-I5', user])

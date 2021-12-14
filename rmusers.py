#!/usr/bin/env python3

import os
import subprocess
import sys
from pwd import getpwnam

if os.geteuid() != 0:
    sys.exit('You must be root')

data_dir = os.getenv("DATA") or sys.argv[1]
authorized_users_file = os.path.join(data_dir, "authorized_users")
existing_users_file = os.path.join(data_dir, "existing_users")
unauthed_file = os.path.join(data_dir, "unauthorized_users")

authorized_users = []
with open(authorized_users_file, "r") as f:
    authorized_users = list(filter(None, f.read().split(sep='\n')))

existing_users = []
with open(existing_users_file, "r") as f:
    existing_users = list(filter(None, f.read().split(sep='\n')))

with open(unauthed_file, "w") as f:
    for user in existing_users:
        if user not in authorized_users:
            uid = str(getpwnam(user).pw_uid)
            subprocess.call(['deluser', "--remove-home", user])
            f.write(user + "\n")
            print("User " + user + " (" + uid + ") removed")
        else:
            subprocess.call(['chage', '-M90', '-m1', '-W7', '-I30', user])

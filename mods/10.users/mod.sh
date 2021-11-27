usermod -g 0 root

# *** Change password ***
# TEST: see if other users get Password123! and autologin gets password
pinfo 'Change passwords (might take a while)...'
sed '/^$/d;s/^ *//;s/ *$//;s/$/:Password123!/' $DATA/authorized_users > "$DATA/chpw"

# pipe into xargs to trim
autologin_user=$(cat $DATA/autologin_user | xargs)
sed -i "s/$autologin_user:.*/$autologin_user:password/" "$DATA/chpw"
chpasswd < "$DATA/chpw"
psuccess 'Change passwords (might take a while)... Done'

# *** Remove unauthorized users and run chage on valid users ***
awk -F: '$3 >= 1000 && $1 != "nobody" {print $1}' /etc/passwd > "$DATA/existing_users"
python3 $BASE/rmusers.py $DATA
psuccess "Removed unauthorized users"

gawk -i inplace -F: '$3 != 0 || ($3 == 0 && $1 == "root") {print $0}' /etc/passwd
for user in `awk -F: '($3 < 1000) {print $1 }' /etc/passwd`; do
    if [ $user != "root" ]; then
        usermod -L $user
        if [ $user != "sync" ] && [ $user != "shutdown" ] && [ $user != "halt" ]; then
            usermod -s /usr/sbin/nologin $user
        fi
    fi
done
psuccess "Ensured that no system user has usable password & login shell"

# *** Lock root ***
passwd -l root
psuccess "Locked root user"

# *** Change sudoers ***
# TEST: didn't seem to work in R2
authorized_sudoers=$(cat $DATA/authorized_sudoers)
sed -i "s/^sudo:x:(\d+):.*$/sudo:x:\$1:$authorized_sudoers/" /etc/group
psuccess "Corrected sudo group members"

# *** Sudo config ***
mkdir -p $BACKUP/sudoers
mv /etc/sudoers.d/* $BACKUP/sudoers
install -o root -g root -Dm 440 $RC/sudoers /etc/sudoers
psuccess "Installed secure sudoers config"

# *** PAM config ***
instconf $RC/common-account /etc/pam.d/common-account
instconf $RC/common-password /etc/pam.d/common-password
instconf $RC/common-session /etc/pam.d/common-session
instconf $RC/common-session-noninteractive /etc/pam.d/common-session-noninteractive
instconf $RC/common-auth /etc/pam.d/common-auth
# TODO: install defaults for binary-specific pam configs as well
instconf $RC/pwquality.conf /etc/security/pwquality.conf
rm -rf /etc/security/pwquality.conf.d
psuccess "Installed secure PAM config"

# *** Miscellaneous ***
instconf $RC/login.defs /etc/login.defs
useradd -D -f 30
psuccess "Installed miscellaneous configs"

if [ ! -f $MOD/keep_nopasswdlogin ]; then
    delgroup -f nopasswdlogin
fi

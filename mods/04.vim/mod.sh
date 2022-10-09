#!/usr/bin/env bash
pinfo "Removing pre-existing vim configurations"
autologin_user=$(cat $DATA/autologin_user | xargs)
if [[ -f $DATA/vim-backed-up ]]; then
    mv -f /root/.vimrc{,.bak}
    mv -f /home/$autologin_user/.vimrc{,.bak}
    mv -f /root/.vim{,.bak}
    mv -f /home/$autologin_user/.vim{,.bak}
    touch $DATA/vim-backed-up
fi

pinfo "Installing configurations"
instconf $RC/vimrc /etc/vim/vimrc
instconf $RC/vimrc.local /etc/vim/vimrc.local

plug_dir=".vim/pack/plugins/start"

pinfo "Installing plugins"
git clone https://github.com/joshdick/onedark.vim /root/${plug_dir}/onedark.vim
git clone https://github.com/itchyny/lightline.vim /root/${plug_dir}/lightline.vim
cp -r /root/${plug_dir}/onedark.vim /home/${autologin_user}/${plug_dir}/onedark.vim
cp -r /root/${plug_dir}/lightline.vim /home/${autologin_user}/${plug_dir}/lightline.vim

pinfo "Creating symlinks (vim to neovim)"
mkdir -p /root/.config/nvim
mkdir -p /home/${autologin_user}/.config/nvim
ln -sf /etc/vim /root/.config/nvim 
ln -sf /etc/vim /home/${autologin_user}/.config/nvim 
ln -sf /etc/vimrc.local /root/.config/nvim/init.vim
ln -sf /etc/vimrc.local /home/${autologin_user}/.config/nvim

psuccess "Configured vim and neovim"

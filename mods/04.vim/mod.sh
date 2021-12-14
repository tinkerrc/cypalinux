pinfo "Removing pre-existing vim configurations"
autologin_user=$(cat $DATA/autologin_user | tr -d '\n')
rm /root/.vimrc /home/$autologin_user/.vimrc
rm -r /root/.vim /home/$autologin_user/.vim

pinfo "Installing configurations"
instconf $RC/vimrc /etc/vim/vimrc
instconf $RC/vimrc.local /etc/vim/vimrc.local

plug_dir=".vim/pack/plugins/start"

pinfo "Installing plugins"
git clone https://github.com/joshdick/onedark.vim /root/${plug_dir}/onedark.vim
git clone https://github.com/itchyny/lightline.vim /root/${plug_dir}/lightline.vim
cp -r /root/${plug_dir}/onedark.vim /home/${autologin_user}/${plug_dir}/onedark.vim
cp -r /root/${plug_dir}/lightline.vim /home/${autologin_user}/${plug_dir}/lightline.vim

pinfo "Symlinking .vim to .config/nvim"
ln -s ~/.vim /root/.config/nvim 
ln -s ~/.vim /home/${autologin_user}/.config/nvim 

psuccess "Configured vim and neovim"

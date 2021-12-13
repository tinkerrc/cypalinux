# TODO: set up colorscheme (onedark); need to download first (have it ready in filesystem)
# TODO: set up a default set of keybindings
# TODO: apply config to root and autologin user
# TODO: symlink .vimrc to .config/neovim/init.vim

autologin_user=$(cat $DATA/autologin_user | tr -d '\n')
rm /root/.vimrc /home/$autologin_user/.vimrc
rm -r /root/.vim /home/$autologin_user/.vim

instconf $RC/vimrc /etc/vim/vimrc
instconf $RC/vimrc.local /etc/vim/vimrc.local

plug_dir=".vim/pack/plugins/start"
git clone https://github.com/joshdick/onedark.vim /root/${plug_dir}/onedark.vim
git clone https://github.com/itchyny/lightline.vim /root/${plug_dir}/lightline.vim
cp -r /root/${plug_dir}/onedark.vim /home/${autologin_user}/${plug_dir}/onedark.vim
cp -r /root/${plug_dir}/lightline.vim /home/${autologin_user}/${plug_dir}/lightline.vim

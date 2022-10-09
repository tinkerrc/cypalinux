#!/usr/bin/env bash
apti vim neovim gawk sed
[ -x /usr/bin/nvim ] && alias vim="/usr/bin/nvim" || alias nvim="/usr/bin/vim"
psuccess "Installed core dependencies"

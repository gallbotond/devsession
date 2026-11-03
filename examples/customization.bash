# Reviewed, reusable shell configuration. No host .bashrc or agents are sourced.
# Install/copy this on the host too if you want these exact customizations there.
HISTCONTROL=ignoreboth
shopt -s histappend checkwinsize
alias ls='ls --color=auto'
alias ll='ls -alF'
alias la='ls -A'
alias l='ls -CF'
alias grep='grep --color=auto'
function project_root { printf '%s\n' "$PWD"; }
source /usr/share/bash-completion/bash_completion
if command -v oh-my-posh >/dev/null; then
    eval "$(oh-my-posh init bash)"
else
    PS1='[${DEVSESSION}] \u@\h:\w\$ '
fi

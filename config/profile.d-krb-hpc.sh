# /etc/profile.d/krb-hpc.sh (login nodes): every CAC login refreshes the TGT in
# $HOME/.krb5 via krb-credd and points KRB5CCNAME at it.
if [ -S /run/krb-hpc/credd.sock ] && [ -z "${KRB_HPC_DONE:-}" ]; then
    _k=$(krb-get 2>/dev/null) && eval "$_k" && export KRB_HPC_DONE=1
    unset _k
fi

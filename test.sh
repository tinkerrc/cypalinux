set -au

source harden.sh

reset-test() {
    rm -f $DATA/test
    unmask welcome
    unmask recon
    unmask backup
    unmask apt-src
    unmask core-deps
    unmask vim
    unmask config
}
setup-test() {
        pinfo "Setting up test"
        run-mod apt-src
        run-mod core-deps
        run-mod vim

        run-mod config

        pwarn "Note: all interactive modules (except 'start') will be masked unless reset-test is invoked"

        todo "Take a snapshot of the VM"

        mask welcome
        mask recon
        mask backup
        mask apt-src
        mask core-deps
        mask vim
        mask config

        touch $DATA/test
}

test-harden() {
    if ! [ -f $DATA/test ]; then
        setup-test
    fi

    harden

    psuccess "Test completed. Restarting VM in 5 seconds."
    sleep 5
    reboot
}



set -au

source harden.sh

reset-test() {
    rm /tmp/cypa_test
}

test-harden() {
    if ! [ -f /tmp/cypa_test ]; then
        pinfo "Setting up"
        run-mod apt-src
        run-mod core-deps

        ready "You will be prompted to configure the test. Note that configurations will not be reset unless reset-test() is invoked."
        run-mod config
    fi
    pinfo "Testing will begin in 5 seconds"
    sleep 5

    mask welcome
    mask recon
    mask backup
    mask apt-src
    mask core-deps
    mask config

    harden

    unmask welcome
    unmask recon
    unmask backup
    unmask apt-src
    unmask core-deps
    unmask config

    psuccess "Test completed. Restarting VM in 5 seconds"
    sleep 5
    reboot
}



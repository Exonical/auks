#!/usr/bin/env bats

KADMIN="kadmin -p kadmin/admin -w password"
USER_KEYTAB=/tmp/client-user.keytab
USER_CCACHE=/tmp/client-user.ccache

setup() {
    if ! $KADMIN list_principals | grep -Fx 'user@EXAMPLE.COM'; then
        $KADMIN add_principal -randkey user
    fi
    rm -f "$USER_KEYTAB" "$USER_CCACHE"
    $KADMIN ktadd -k "$USER_KEYTAB" user
    chmod 0600 "$USER_KEYTAB"
}

teardown() {
    kdestroy -c "FILE:$USER_CCACHE" || true
    auks -f /conf/auks.conf --remove --uid 1234 >/dev/null 2>&1 || true
    rm -f "$USER_KEYTAB" "$USER_CCACHE"
}

@test "Rust client can ping auksd" {
    auksctl-rs -c /conf/auks.conf ping
}

@test "Rust add/get is byte-compatible with the C client" {
    kinit -k -t "$USER_KEYTAB" -c "$USER_CCACHE" user
    export KRB5CCNAME="FILE:$USER_CCACHE"

    auksctl-rs -c /conf/auks.conf add "$KRB5CCNAME"
    run auksctl-rs -c /conf/auks.conf get 1234
    [ "$status" -eq 0 ]
    [[ "$output" == *"principal=user@EXAMPLE.COM"* ]]

    run auks -f /conf/auks.conf -g -u 1234
    [ "$status" -eq 0 ]
    klist -c "$USER_CCACHE" | grep -F 'user@EXAMPLE.COM'
}

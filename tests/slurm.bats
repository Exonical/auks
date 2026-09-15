#!/usr/bin/env bats

KADMIN="kadmin -p kadmin/admin -w password"
USER_KEYTAB=/tmp/slurm-user.keytab
ADMIN_KEYTAB=/tmp/slurm-admin.keytab
USER_CCACHE=/tmp/slurm-user.ccache

setup() {
    if ! $KADMIN list_principals | grep -Fx 'user@EXAMPLE.COM'; then
        $KADMIN add_principal -randkey user
    fi
    if ! $KADMIN list_principals | grep -Fx 'admin@EXAMPLE.COM'; then
        $KADMIN add_principal -randkey admin
    fi
    rm -f "$USER_KEYTAB" "$ADMIN_KEYTAB"
    $KADMIN ktadd -k "$USER_KEYTAB" user
    $KADMIN ktadd -k "$ADMIN_KEYTAB" admin
    chmod 0600 "$USER_KEYTAB" "$ADMIN_KEYTAB"
}

teardown() {
    kdestroy || true
    rm -f "$USER_CCACHE" /tmp/out.* /tmp/krb5cc_1234_*
    kinit -k -t "$ADMIN_KEYTAB" admin
    auks -f /conf/auks.conf --remove --uid 1234 &>/dev/null || true
    $KADMIN delete_principal -force user || true
    $KADMIN delete_principal -force admin || true
    kdestroy || true
    rm -f "$USER_KEYTAB" "$ADMIN_KEYTAB"
}

prepare_user() {
    kdestroy || true
    kinit -k -t "$USER_KEYTAB" -c "$USER_CCACHE" user
    export KRB5CCNAME="FILE:$USER_CCACHE"
    auks -f /conf/auks.conf --add
    unset KRB5CCNAME
    kinit -k -t "$USER_KEYTAB" user
}

@test "srun with --auks=yes gets a ticket" {
    prepare_user
    run srun --auks=yes klist
    [ "$status" -eq 0 ]
    [[ "$output" == *"user@EXAMPLE.COM"* ]]

    run srun --auks=yes sh -c 'echo "$KRB5CCNAME"'
    [ "$status" -eq 0 ]
    [ "$output" != "FILE:$USER_CCACHE" ]
}

@test "SLURM_SPANK_AUKS=no in the job env disables forwarding" {
    prepare_user
    kdestroy
    export SLURM_SPANK_AUKS=no
    unset KRB5CCNAME
    run srun klist
    [ "$status" -ne 0 ]
    [[ "$output" != *"user@EXAMPLE.COM"* ]]
}

@test "srun --auks=no alone is not honoured on the node (AUDIT A11)" {
    prepare_user
    unset SLURM_SPANK_AUKS
    # Documents current behaviour: the option is not propagated to the remote side. Flip this assertion when A11 is fixed.
    run srun --auks=no klist
    [ "$status" -eq 0 ]
    [[ "$output" == *"user@EXAMPLE.COM"* ]]
}

@test "ccache is destroyed after the step" {
    prepare_user
    run srun --auks=yes sh -c 'echo "$KRB5CCNAME"'
    [ "$status" -eq 0 ]
    cache_path="${output#FILE:}"
    [ -n "$cache_path" ]
    [ ! -e "$cache_path" ]
}

@test "sbatch job sees the ticket" {
    prepare_user
    run sbatch --wait --auks=yes --output=/tmp/out.%j --wrap klist
    [ "$status" -eq 0 ]
    output_file=$(find /tmp -maxdepth 1 -name 'out.*' -type f | head -1)
    [ -n "$output_file" ]
    run cat "$output_file"
    [ "$status" -eq 0 ]
    [[ "$output" == *"user@EXAMPLE.COM"* ]]
}

@test "renewer is running during the step and gone after" {
    prepare_user
    run srun --auks=yes sh -c 'pgrep -u "$(id -u)" -f "auks -R loop"'
    [ "$status" -eq 0 ]
    run pgrep -u "$(id -u)" -f "auks -R loop"
    [ "$status" -ne 0 ]
}

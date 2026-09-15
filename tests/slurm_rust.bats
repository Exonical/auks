#!/usr/bin/env bats

KADMIN="kadmin -p kadmin/admin -w password"
USER_KEYTAB=/tmp/slurm-rust-user.keytab
ADMIN_KEYTAB=/tmp/slurm-rust-admin.keytab

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
    : > /var/log/slurm/slurmd.log
}

teardown() {
    kdestroy || true
    $KADMIN delete_principal -force user || true
    $KADMIN delete_principal -force admin || true
    kdestroy || true
    rm -f "$USER_KEYTAB" "$ADMIN_KEYTAB"
}

wait_for_log() {
    for _ in $(seq 1 30); do
        grep -q "$1" /var/log/slurm/slurmd.log && return 0
        sleep 1
    done
    return 1
}

@test "srun help lists the auks option" {
    run srun --help
    [ "$status" -eq 0 ]
    [[ "$output" == *"--auks"* ]]
}

@test "srun --auks=yes reaches the Rust plugin" {
    run srun --auks=yes true
    [ "$status" -eq 0 ]
    wait_for_log 'spank-auks-rs: init_post_opt mode=Enabled'
}

@test "default disabled mode does not create a ticket" {
    run srun true
    [ "$status" -eq 0 ]
    wait_for_log 'spank-auks-rs: init_post_opt mode=Disabled'
    run srun klist
    [ "$status" -ne 0 ]
}

@test "srun --auks=no is propagated to the node" {
    run env SLURM_SPANK_AUKS=yes srun --auks=no env
    [ "$status" -eq 0 ]
    [[ "$output" == *"SLURM_SPANK_AUKS=no"* ]]
    wait_for_log 'spank-auks-rs: init_post_opt mode=Disabled'
}

@test "invalid --auks value fails" {
    run srun --auks=bogus true
    [ "$status" -ne 0 ]
}

#!/usr/bin/env bats

KADMIN="kadmin -p kadmin/admin -w password"
USER_KEYTAB=/tmp/slurm-rust-user.keytab
ADMIN_KEYTAB=/tmp/slurm-rust-admin.keytab
USER_CCACHE=/tmp/slurm-rust-user.ccache

setup() {
    if ! $KADMIN list_principals | grep -Fx 'user@EXAMPLE.COM'; then
        $KADMIN add_principal -randkey user
    fi
    if ! $KADMIN list_principals | grep -Fx 'admin@EXAMPLE.COM'; then
        $KADMIN add_principal -randkey admin
    fi
    rm -f "$USER_KEYTAB" "$ADMIN_KEYTAB" "$USER_CCACHE"
    $KADMIN ktadd -k "$USER_KEYTAB" user
    $KADMIN ktadd -k "$ADMIN_KEYTAB" admin
    chmod 0600 "$USER_KEYTAB" "$ADMIN_KEYTAB"
}

teardown() {
    kdestroy -c "FILE:$USER_CCACHE" || true
    kdestroy || true
    kinit -k -t "$ADMIN_KEYTAB" admin
    auks -f /conf/auks.conf --remove --uid 1234 >/dev/null 2>&1 || true
    kdestroy || true
    $KADMIN delete_principal -force user || true
    $KADMIN delete_principal -force admin || true
    rm -f "$USER_KEYTAB" "$ADMIN_KEYTAB" "$USER_CCACHE"
}

prepare_user() {
    kdestroy || true
    kinit -k -t "$USER_KEYTAB" -c "$USER_CCACHE" user
    export KRB5CCNAME="FILE:$USER_CCACHE"
    auks -f /conf/auks.conf --add
    unset KRB5CCNAME
    kinit -k -t "$USER_KEYTAB" user
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

@test "srun with --auks=yes gets a ticket" {
    prepare_user
    run srun --auks=yes klist
    [ "$status" -eq 0 ]
    [[ "$output" == *"user@EXAMPLE.COM"* ]]
    wait_for_log "user '1234' cred stored in ccache"
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

@test "srun --auks=no is honoured on the node" {
    prepare_user
    kdestroy
    unset SLURM_SPANK_AUKS
    run srun --auks=no klist
    [ "$status" -ne 0 ]
    [[ "$output" != *"user@EXAMPLE.COM"* ]]
}

@test "SLURM_SPANK_AUKS=yes cannot override --auks=no remotely" {
    prepare_user
    kdestroy
    run env SLURM_SPANK_AUKS=yes srun --auks=no klist
    [ "$status" -ne 0 ]
    [[ "$output" != *"user@EXAMPLE.COM"* ]]
    run env SLURM_SPANK_AUKS=yes srun --auks=no env
    [ "$status" -eq 0 ]
    [[ "$output" == *"SLURM_SPANK_AUKS=no"* ]]
}

@test "ccache is destroyed after the step" {
    prepare_user
    run srun --auks=yes sh -c 'echo "$KRB5CCNAME"'
    [ "$status" -eq 0 ]
    cache_name="$output"
    wait_for_log "Destroyed ccache $cache_name"
    if [[ "$cache_name" == FILE:* ]]; then
        run klist -c "$cache_name"
        [ "$status" -ne 0 ]
    fi
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
    wait_for_log "credential renewer launched"
    run pgrep -u "$(id -u)" -f "auks -R loop"
    [ "$status" -ne 0 ]
    wait_for_log "all tasks exited, killing credential renewer"
}

@test "renewer is isolated from the step environment and descriptors" {
    prepare_user
    run srun --auks=yes sh -c '
        pid=$(pgrep -f "[a]uks -R loop" | head -1)
        test -n "$pid"
        tr "\0" "\n" < "/proc/$pid/environ" > /tmp/renewer-env
        ! grep -q "^SLURM_" /tmp/renewer-env
        grep -q "^KRB5CCNAME=" /tmp/renewer-env
        grep -q "^AUKS_CONF=/conf/auks.conf$" /tmp/renewer-env
        test "$(find "/proc/$pid/fd" -mindepth 1 -maxdepth 1 -printf "%f\n" | sort | tr "\n" " ")" = "0 1 2 "
    '
    [ "$status" -eq 0 ]
}

@test "invalid --auks value fails" {
    run srun --auks=bogus true
    [ "$status" -ne 0 ]
}

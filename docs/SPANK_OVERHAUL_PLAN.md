# SPANK plugin overhaul and Rust migration plan

Derived from `AUDIT.md`. Two goals, delivered together:

1. A SPANK plugin that is correct against the SPANK contract as documented
   (not as observed), keeps no cross-hook global state, does privileged work
   in the smallest window possible, and is tested in CI against a real Slurm.
2. Migration of AUKS to Rust — plugin first, then the client side (library,
   CLI, renewer), then `auksd`/`auksdrenewer` — without a flag-day: every
   Rust component speaks today's wire protocol and reads today's config
   files, so C and Rust binaries can be mixed during rollout.

Nothing below is implemented; each phase is sized to be reviewable as one PR
or a short series. Facts about third-party crates were checked on
crates.io/docs.rs at planning time and are summarised in §"Ecosystem
survey"; re-verify before depending on them.

## Guiding decisions

### D1. Keep MIT libkrb5; bind it ourselves

A pure-Rust Kerberos stack (`krb5-rs`, `rskrb5`, `kerbeiros`, `picky-krb`,
`kerbcore`) is not mature enough for a credential vault: none of them
ships a production-grade combination of `KRB-CRED` forwarding, `KRB-PRIV`
streams, replay cache, TGS renewal and MIT ccache-collection semantics, and
the two that come closest are pre-1.0 with < 100 downloads (`krb5-rs`
explicitly lists TGT renewal as unimplemented). Licensing is also mixed
(AGPL-3.0 for `kerbeiros`).

Existing libkrb5 bindings are either unmaintained (`krb5-sys` 0.3.0 from
2019, "incomplete"; `libkrb5[-sys]` 0.0.3 from 2022), GPL-3.0
(`kerberos-sys`), or brand new (`kurbu5-sys`). AUKS uses a small, stable
subset of the API (~25 functions), so we own the binding:

* `auks-krb5-sys`: `bindgen` at build time against the system `krb5.h`
  with an allowlist of exactly the symbols we use. No vendored library
  (`krb5-src` pins 1.19.2; we want the distro's krb5 for CVE fixes and
  `krb5.conf` behaviour).
* `auks-krb5`: safe wrappers — `Context`, `Principal`, `Ccache`
  (`new_unique`, `switch`, `destroy`, `store`, `default_name`), `Creds`
  (`get_tgt`, `renew`, `mk_ncred`/`rd_cred` for the serialised blob,
  `deladdr` via TGS, `cross_realm`), `AuthStream` (`sendauth`/`recvauth`,
  `mk_priv`/`rd_priv` with `DO_SEQUENCE`, NAT/rcache flags),
  `aname_to_localname`. Every `krb5_error_code` becomes a typed error
  carrying `krb5_get_error_message`.

`krb5-rs` (Exonical fork) re-evaluated 2026-09: AS/TGS + KRB-PRIV/CRED ASN.1
types present, no ccache/keytab I/O, no AP exchange/sendauth, no renewal;
revisit when those land.

### D2. Wire compatibility is a hard requirement for Phases 1-4

`auks-proto` re-implements `auks_buffer`/`auks_message` byte-for-byte
(`htonl` ints, `uid` as `int`, raw `len`+bytes; request/reply type numbers
from `auks_message.h`) and `auks-cred` re-implements the serialised
`auks_cred_t` (`info` struct + `krb5_mk_ncred` payload). Compatibility is
proven by differential tests, not by reading: the compose rig runs every
combination of {C, Rust} × {client, daemon} through `tests/simple.bats`.

A GSSAPI-based protocol v2 (`libgssapi` 0.11 is maintained and covers
`init/accept_sec_context` + `wrap/unwrap`) is attractive but is a
wire-protocol break. It is parked under Phase 5 together with the
job-scoped authorisation work (A1), which needs a new message type anyway.

### D3. SPANK plugin in Rust as a `cdylib` with the exact C ABI

Slurm loads the plugin by `dlopen` and resolves fixed symbols. From
`slurm/spank.h` (master):

```c
#define SPANK_PLUGIN(__name, __ver)
  const char plugin_name[] = #__name;
  const char plugin_type[] = "spank";
  const unsigned int plugin_version = SLURM_VERSION_NUMBER;
  const unsigned int spank_plugin_version = __ver;   /* absent in 20.11, present in master */
typedef int (spank_f)(spank_t, int ac, char *argv[]);
```

We export `plugin_name`, `plugin_type`, `plugin_version`,
`spank_plugin_version` and the five `#[no_mangle] extern "C" fn
slurm_spank_{init,init_post_opt,user_init,task_exit,exit}` we need
(`local_user_init` may be added). `plugin_version` must match the loading
Slurm's `SLURM_VERSION_NUMBER`, so the crate reads it from the `slurm.h`
it is built against — one build per supported Slurm major.minor, exactly as
today.

Sharp edge: `spank_get_item` is variadic with item-dependent argument
types. The FFI layer exposes typed accessors only (`job_id() ->
Result<u32>`, `job_uid() -> uid_t`, `job_gid()`, `local_task_count()`,
`task_exit_status()`), never a variadic passthrough.

Prior art: `slurm-spank` 0.4.1 (`fdiakh/slurm-spank-rs`, Apache-2.0,
updated 2025-11) provides `SPANK_PLUGIN!`, a `Plugin` trait, typed
`get_item` and option registration. Decision: **prototype on
`slurm-spank` in Phase 1**; if its MSRV, Slurm-version coverage or hook
set does not fit, replace it with our own ~300-line shim (`auks-spank-sys`)
— the surface we need is small. Either way the plugin logic depends on a
trait, not on the crate.

### D4. One state struct per step, work in the right hook

Unchanged from the C-side design, now enforced by the language:

* `struct Conf` parsed once from `plugstack.conf` args (table-driven; unknown
  key → `ESPANK_BAD_ARG` + `slurm_error`). `struct StepCtx { mode, jobid,
  uid, gid, cred: Option<SerialisedCred>, ccache: Option<CcacheName>,
  renewer: Option<Child> }` created in `slurm_spank_init`, stored behind a
  `OnceLock<Mutex<…>>` (Slurm calls hooks from one thread but we don't rely
  on it), dropped in `slurm_spank_exit`.
* `slurm_spank_init` (remote): options + `S_JOB_*` items; no network.
* `slurm_spank_init_post_opt` (remote, root): final mode; `GET` from auksd
  using the host ccache into memory (`cred: Some(..)`). No uid switching.
* `slurm_spank_user_init` (remote, euid=user, inside job container): create
  ccache with the *user's* default type (`krb5_cc_default_name` after
  Slurm's privilege drop → honours `/run/user/%{uid}` / `KEYRING` policy),
  store, `cc_switch` unless disabled, `spank_setenv KRB5CCNAME`, run
  helper (with timeout), spawn renewer. Removes the per-thread
  `syscall(SYS_setresuid)` hack entirely.
* `slurm_spank_task_exit` (last task) and `slurm_spank_exit`: stop renewer,
  destroy ccache; `exit` is the authoritative teardown.

Settled (AUDIT A3): every Slurm from 20.11 to 24.11 runs `user_init`
either in-process or in a `clone(CLONE_VM)` child, so in-memory `StepCtx`
is safe; no state file needed. Under `contain_spank` the renewer is not
our child, so D5 must not rely on `waitpid` for shutdown confirmation
(pidfd / `kill(pid, 0)` polling instead).

### D5. Renewer as a supervised child

`std::process::Command` with `pre_exec` doing `setsid()` and a
`close_range(3, ~0)` sweep (Rust already sets `CLOEXEC` on fds it opens;
inherited `slurmstepd` fds do not get that for free), `stdio` to
`/dev/null`, env limited to `KRB5CCNAME`, `AUKS_CONF`, `PATH`. Handle kept
as a pidfd (`pidfd_open`, Linux ≥ 5.3; fallback pid + `/proc/<pid>/stat`
start-time check). Shutdown: `SIGTERM`, wait ≤ 5 s, `SIGKILL`. The Rust
`auks -R loop` handles `SIGTERM` and exits without touching the ccache.

### D6. Fail loudly

Any failure in enabled mode returns `ESPANK_ERROR` with a
`slurm_error` message; docs recommend `required` for kerberised partitions.

### D7. Toolchain and packaging

* Toolchain (decided): **rustup-managed stable**, pinned per release via
  `rust-toolchain.toml`; edition 2024; no distro-compiler constraint, so
  the EL8 1.75 / EL9 1.79–1.88 AppStream compilers are irrelevant and crate
  MSRVs are not a selection criterion. Bump the pin deliberately, in its
  own PR, with `cargo +<new> test` green.
* Build: Cargo workspace under `rust/`; autotools keeps building the C
  components until each is retired, and gains a `--enable-rust` switch that
  runs `cargo build --release --locked` and installs the artefacts to the
  same paths. RPM: `cargo vendor` tarball as `Source1`; the spec installs
  the pinned toolchain via rustup in `%build` (or the build container ships
  it) rather than depending on `rust-toolset`. `Dockerfile`/`compose.yaml`
  images gain the same rustup step so CI and packaging use one compiler.
* Binary names and paths are unchanged (`/usr/bin/auks`, `/usr/sbin/auksd`,
  `$libdir/slurm/auks.so`), so `plugstack.conf`, systemd units, `aukspriv`
  and the HOWTO stay valid.

### D8. Test everything through the compose rig

Extend `compose.yaml` with `slurmctld`+`slurmd`+`munge`, build both the C
and Rust plugin with `--with-slurm`, and add bats cases that submit jobs and
assert on `klist` inside the step. Rust unit tests cover `auks-proto`
(golden byte vectors captured from the C implementation), ACL parsing and
config parsing.

## Workspace layout

```
rust/
  Cargo.toml            workspace, edition 2024, lints (unsafe_op_in_unsafe_fn, missing_docs on pub)
  auks-krb5-sys/        bindgen allowlist over krb5.h            (Phase 1)
  auks-krb5/            safe wrappers (D1)                        (Phase 1)
  auks-proto/           buffer/message codec, request/reply enums (Phase 1)
  auks-cred/            auks_cred_t (info + blob), pack/unpack    (Phase 1)
  auks-config/          auks.conf / auks.acl parsers (same grammar, `nom`
                        or hand-rolled; case-insensitive keys)    (Phase 2)
  auks-client/          AuksClient: connect/retry/failover, ping/add/get/
                        remove/dump, helper-script runner         (Phase 2)
  auks-spank/           cdylib → auks.so                          (Phase 1-2)
  auks-cli/             `auks` binary incl. `-R loop` renewer     (Phase 3)
  auksd/                daemon: acceptor + worker pool (std threads, no
                        async runtime needed at this scale), repo, cleaner,
                        on-disk aukscc_<uid> FILE ccaches         (Phase 4)
  auksdrenewer/                                                    (Phase 4)
```

`pam_auks` stays in C (it only does ADD and is 200 lines) until `auks-client`
is stable; then it becomes a thin cdylib using the same crate, as a Phase 4
follow-up.

## Phases

### Phase 0 — safety net (C, no behaviour change)

* ~~CI: build `auks.so` with `--with-slurm` against a pinned Slurm; plugin
  compiled with `-Wall -Wextra -Wformat=2 -Werror` (catches A5).~~ done (PR #2).
* ~~Fix A5 (`%u` argument), A4 (`umask(077)`), guard `kill()` in `task_exit`.~~ done (PR #2).
* ~~Compose: Slurm node + `auks.so required` + bats~~ done: Rocky Linux 10
  image, Slurm 26.05.4 built from source (`auth/slurm`, `CgroupPlugin=disabled`),
  `tests/slurm.bats` covers `srun`/`sbatch --auks=yes`, env-var disable,
  ccache destruction, renewer lifecycle — and pins the A11 defect
  (`--auks=no` alone is not honoured on the node) until D3/Phase 2 fixes it.
* Settle remaining Audit D items (`job_container/tmpfs`, KEYRING
  ownership, fd leak) and record answers in `AUDIT.md`. CLONE_VM: done.
* Capture golden wire vectors from the C client/daemon (`tcpdump` of the
  post-`rd_priv` plaintext via a debug hook, or unit-level `auks_buffer`
  dumps) for `auks-proto` tests.

### Phase 1 — Rust foundations + plugin skeleton

* `auks-krb5-sys`, `auks-krb5`, ~~`auks-proto`, `auks-cred` with unit tests
  against the golden vectors~~ done (Phase 1a PR).
* `auks-spank` exporting the SPANK ABI (D3) and implementing **only** mode
  decision + `spank_setenv` passthrough; loaded by the compose Slurm to
  prove the ABI, option registration (`--auks=`), `plugstack.conf` parsing
  and logging. Deliverable: Rust `auks.so` loads and behaves as a no-op
  with `default=disabled`.
* Autotools `--enable-rust` plumbing; RPM builds both artefacts.

### Phase 2 — Rust plugin at parity, C plugin retired

* `auks-client` (connect/retry/failover/`GET`), `auks-config`.
* Full D4/D5 lifecycle in `auks-spank`. Compatibility shims: accept all
  current `plugstack.conf` args; `force_file_ccache`, `sync=` accepted with
  a deprecation warning and no effect; `spankstackcred=yes` publishes
  `AUKS_KRB5CCNAME` via `spank_setenv`/`spank_job_control_setenv` instead of
  mutating `slurmstepd`'s env (documented change for downstream plugins).
* `enforced` → `strict` (alias kept), applies to both client add failure
  and remote GET failure. `SLURM_SPANK_AUKS` set with overwrite from the
  option callback for every value (fixes A11); remote `--auks=` wins over
  env. Flip the A11 assertion in `tests/slurm.bats`.
* Renewer still the **C** `auks -R loop` at this stage (spawned by the Rust
  plugin) — this keeps the phase to one component.
* Gate: Slurm bats suite green with Rust plugin against the C daemon;
  `tests/simple.bats` untouched and green.
* Delete `src/plugins/slurm/`; update `slurm-spank-auks.conf`, `auks.so.8`,
  `HOWTO`.

### Phase 3 — Rust CLI and renewer

* `auks-cli`: same flags as `src/auks/auks.c` (`-p -a -g -r -d -R once|loop
  -u -C -f -v …`), same exit codes/messages where scripts may depend on
  them; `-R loop` gets `SIGTERM` handling, jitter, and structured logging.
* Gate: full `tests/simple.bats` green with Rust CLI ↔ C daemon **and**
  C CLI ↔ C daemon (unchanged). Delete `src/auks/`.

### Phase 4 — Rust daemon

* `auksd`: `krb5_recvauth` via `auks-krb5`; ACL with the B1/B2 fixes
  (peer address actually passed; regexes anchored and precompiled at load;
  no DNS on the request path); repository with the same `aukscc_<uid>`
  on-disk format so a C→Rust daemon switch keeps existing creds; cleaner;
  `Workers`/`QueueSize`/`RepoSize`/`CleanDelay` honoured. Same systemd unit.
* `auksdrenewer`.
* Gate: 2×2 differential matrix (C/Rust client × C/Rust daemon) green;
  `auks -d` output identical. Delete `src/auksd/`, `src/api/`, confparse,
  xternal; autotools reduced to PAM, or replaced by Cargo + a `Makefile`
  for install layout (decide then).
* `pam_auks` as Rust cdylib (follow-up).

### Phase 5 — protocol v2 and job-scoped authorisation (design first)

Requires a design doc before code. Candidates from the audit (A1):

* **Controller-minted token**: `slurmctld`-side plugin/prolog obtains a
  per-job token (HMAC over `jobid,uid,expiry`) from auksd and puts it in
  the job env; `slurmstepd` sends `GET uid,token`; compute hosts lose
  `admin`. New message type → natural point to also introduce GSSAPI
  framing (`libgssapi`) with version negotiation on connect.
* **Slurm-verified GET**: auksd checks with `slurmctld` that `uid` has a
  running job on the requesting host. No new secret, but a controller RPC
  per step launch.
* **REMOVE on job end** (B4) rides on whichever design gives auksd a job
  notion.

Decision criteria: no new long-lived secrets on compute nodes, no
per-step RPC to `slurmctld` on hot paths, works for `sbatch` jobs whose
`srun` steps start hours later, old C clients keep working until removed.

## Ecosystem survey (checked at planning time)

| Need | Option | Verdict |
|---|---|---|
| libkrb5 FFI | `krb5-sys` 0.3.0 (2019, MIT, "incomplete") · `libkrb5-sys`/`libkrb5` 0.0.3 (2022, unmaintained, safe layer "very limited") · `kerberos-sys` 0.1.1 (2024, GPL-3.0) · `kurbu5-sys` 0.1.4 (2026, BSD-2, very new, targets KDC plugin dev) · `krb5-src` (vendors krb5 1.19.2) | Own bindgen crate (D1) |
| GSSAPI | `libgssapi` 0.11 (MIT, maintained, ~1 M dl) · `cross-krb5` 0.5 (adds SSPI) · `sspi` 0.21 (native, MSRV 1.89) | `libgssapi` for protocol v2 only (Phase 5) |
| SPANK ABI | `slurm-spank` 0.4.1 (Apache-2.0, 2025-11, `SPANK_PLUGIN!` + typed `get_item`) · `slurm-banking-plugins` (bindgen example) | Prototype on `slurm-spank`, fallback own shim (D3) |
| Pure-Rust Kerberos | `krb5-rs` 0.1.0 (renewal not implemented) · `rskrb5` 0.2.0 (renewal advertised, ~94 dl) · `kerbeiros` (AGPL) · `picky-krb` (ASN.1 only, MSRV 1.85) · `kerbcore` (1.88+) | Not now; revisit for Phase 5+ |
| Toolchain | EL8: Rust 1.75 · EL9: 1.79–1.88 · RHEL Rust Toolset modules · rustup stable | rustup stable, pinned in `rust-toolchain.toml` (decided) |

## Non-goals

* Changing the wire protocol or on-disk repository format before Phase 5.
* Rewriting `aukspriv` (bash) — it is a `kinit -k` loop and fine as is.
* Windows/SSPI support.
* Supporting Slurm older than the version pinned in CI.

## Open questions for Bryce

1. ~~Toolchain floor~~ — decided: rustup-managed stable, no distro
   constraint (D7).
2. Target Slurm version(s) — determines which `spank_*` helpers exist and
   whether `contain_spank` is in play (D5).
3. Is `job_container/tmpfs` in use? Raises the priority of D4's
   `user_init` move.
4. Default ccache type on compute nodes (FILE in `/tmp`, KEYRING, KCM,
   `/run/user`)?
5. Is Phase 5 (job-scoped auth / protocol v2) in scope for this effort or
   tracked separately?
6. Should the C components be deleted as each Rust one lands (as planned
   above), or kept in-tree behind `--disable-rust` for one release cycle?

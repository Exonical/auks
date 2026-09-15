# SPANK plugin overhaul plan

Derived from `AUDIT.md`. Goal: a plugin that is correct against the SPANK
contract as documented (not as observed), keeps no cross-hook global state,
does privileged work in the smallest window possible, and is tested in CI
against a real Slurm. Protocol/daemon changes (A1) are scoped as a separate,
later phase so the plugin rewrite can ship against the existing `auksd`.

Nothing below is implemented; each phase is sized so it can be reviewed as
one PR.

## Guiding decisions

1. **Wire compatibility first.** Phases 0-3 talk to today's `auksd` and
   accept today's `plugstack.conf` arguments (with deprecation warnings).
   Operators can upgrade compute nodes independently.
2. **One state struct, keyed by `spank_t`.** All per-step state lives in a
   heap `struct auks_spank_ctx` created in `slurm_spank_init` and freed in
   `slurm_spank_exit`. Options parsed from `plugstack.conf` go into a
   `const` config struct filled once. No file-scope mutable globals except
   the pointer to the ctx.
3. **Move work to the right hook.**
   * `slurm_spank_init` (remote): parse options, read `S_JOB_*` items, decide
     mode. No network, no ccache.
   * `slurm_spank_init_post_opt` (remote): remote `--auks` options are now
     visible; final mode decision.
   * `slurm_spank_user_init` (remote, euid=user, inside job container):
     GET from auksd, create ccache, store, `spank_setenv`, run helper,
     launch renewer. Everything that touches the user's ccache happens
     here, in the user's namespaces, with the real euid rather than a
     per-thread `setresuid` hack.
   * `slurm_spank_task_exit`/`slurm_spank_exit`: stop renewer, destroy
     ccache — driven by ctx state, not by a task counter.

   The GET needs the host credential (root). Two options, decide in Phase 1
   after the CLONE_VM check (Audit D): (a) do the GET in `init_post_opt` as
   root into memory, hand the serialised cred to `user_init` through ctx;
   (b) keep the GET in `user_init` and read `hostcredcache` with a
   `setresuid` round-trip. (a) is preferred: the cred blob is small, and it
   removes all uid juggling from the plugin.
4. **Renewer as a proper child.** Spawn with `posix_spawn`/`fork`+`exec`
   under a `closefrom(3)` sweep, in its own process group/session, with a
   pidfile-free handle (pidfd on Linux ≥ 5.3, else pid + start-time check).
   Give `auks -R loop` a `SIGTERM` handler that destroys nothing (the plugin
   owns the ccache) and exits promptly. Bound `waitpid` with a timeout, then
   `SIGKILL`.
5. **Fail loudly.** Any failure in enabled mode returns `ESPANK_ERROR` with
   a message via `slurm_error`, and `HOWTO` recommends `required` for
   kerberised partitions. `optional` remains a supported deployment but
   stops being the default recommendation.
6. **Test it.** Extend the compose rig with a `slurmctld`+`slurmd` node,
   build `auks.so` with `--with-slurm`, and add bats cases that submit jobs
   and assert on `klist` inside the step.

## Phases

### Phase 0 — safety net (no behaviour change)

* CI: add `--with-slurm` build against a pinned Slurm (`slurm-dev`/`slurm-
  devel`); fail the build on warnings for the plugin (`-Wall -Wextra
  -Wformat=2 -Werror`) — this alone catches A5.
* Fix A5 (missing `%u` argument), A4 (`umask(077)`), guard `kill()` in
  `task_exit`.
* Compose: add a minimal Slurm node (`slurmctld` + `slurmd` on the client
  container, `munge`), plugstack with `auks.so required`, and a bats test:
  `srun --auks=yes klist` shows the forwarded principal;
  `srun --auks=no klist` fails; step exit destroys the ccache.
* Verify the Audit D items and record the answers in `AUDIT.md`.

### Phase 1 — restructure without changing semantics

* Introduce `struct auks_spank_conf` (parsed once) and `struct
  auks_spank_ctx` (per step). Delete the twelve globals.
* Replace prefix `strncmp` option parsing with a table (`key`, `has_value`,
  `handler`); unknown keys → `slurm_error` + `ESPANK_BAD_ARG`.
* Make `SLURM_SPANK_AUKS` handling explicit: client always sets it with
  `overwrite=1`; remote reads it into a bounded buffer and rejects unknown
  values; `--auks=` given on the remote side wins over env.
* Move ccache creation + store + helper + `spank_setenv` from `init` to
  `user_init`; keep the GET where it is for now (root, `init_post_opt`),
  passing the `auks_cred_t` via ctx (decision 3a). Drop the per-thread
  `syscall(SYS_setresuid)` helpers.
* Renewer lifecycle per decision 4; `task_exit` no longer counts tasks —
  `slurm_spank_exit` (remote) is the single teardown point, with
  `task_exit` on the last task as an early optimisation only.
* Replace `sync()` with `fsync` on the ccache fd (FILE type) — keep `sync=`
  as a deprecated alias that logs a warning.
* Remove `force_file_ccache`; `krb5_cc_new_unique` with the *user's*
  default ccache type (resolve via `krb5_cc_default_name` after the uid
  switch, i.e. honouring `default_ccache_name` templates like
  `/run/user/%{uid}/…` or `KEYRING:persistent:%{uid}`) is the only path.
  `no_cc_switch` stays.
* Existing bats tests must pass unchanged; the new Slurm tests must pass.

### Phase 2 — behaviour fixes that operators will notice

* `spankstackcred=yes`: instead of `setenv` in `slurmstepd`, publish the
  ccache path through `spank_job_control_setenv`/`spank_setenv` under a
  documented name (`AUKS_KRB5CCNAME`) and leave `KRB5CCNAME` of the root
  process alone; document the change for downstream plugins.
* `enforced`: rename to `strict`, apply on both sides (missing client cred
  and failed remote GET are both errors).
* Batch/`--export=NONE` path: set `SLURM_SPANK_AUKS` via
  `spank_job_control_setenv` so it survives environment filtering
  **[verify]** Slurm forwards `SLURM_SPANK_*` job-control vars regardless of
  `--export`.
* Structured logging: one `slurm_info` per phase with jobid/stepid/uid; debug
  details behind `slurm_debug2`.
* Update `slurm-spank-auks.conf`, `auks.so.8`, `HOWTO`.

### Phase 3 — daemon-side hardening (independent PR series)

* B1: pass the peer address into `auks_acl_get_role` (from `getpeername`)
  or delete the `host` field from the ACL grammar and docs. Deleting is
  simpler and honest; passing the address is what the docs promise. Either
  way, stop calling `getaddrinfo` on the request path (resolve at ACL load).
* B2: anchor principal regexes at load time (`^(…)$`) unless the rule is
  `*`; precompile.
* B4: add a `REMOVE`-on-job-end hook — the plugin's `slurm_spank_exit` on
  the *batch* step (or a `slurmctld` epilog) can REMOVE when the job's last
  step ends. Requires care with multi-job users: REMOVE only if no other
  running job of that uid exists → needs an `squeue`-style check or a
  refcount in auksd. Defer until A1 is designed.

### Phase 4 — job-scoped authorisation (design item, A1)

The current model (compute host = admin = read any uid) is the largest
residual risk and cannot be fixed by the plugin alone. Candidate designs,
to be evaluated in a design doc before code:

* **Ticket from the controller.** A `slurmctld`-side SPANK/`job_submit`
  plugin (or `slurmctld` prolog) asks auksd for a per-job token (HMAC over
  `jobid,uid,expiry` under a key shared with auksd) and puts it in the job
  environment; `slurmstepd` presents `GET uid,token` and auksd grants
  `user`-equivalent rights for that uid only. Removes `admin` from compute
  nodes entirely. Needs a new message type and a token key in auksd.
* **Slurm-verified GET.** auksd validates the request against `slurmctld`
  (`slurm_load_job` + check that `uid` has a running job allocated to the
  requesting host). Simpler, no new secret, but couples auksd to Slurm and
  adds a controller RPC per step launch.
* **Per-user forwarding without auksd.** Use Kerberos constrained
  delegation or a per-job service ticket instead of forwarding the TGT.
  Largest change; would make auksd a cache rather than a vault.

Decision criteria: no new long-lived secrets on compute nodes, no
per-step RPC to `slurmctld` on hot paths, works for `sbatch` jobs whose
`srun` steps start hours later.

## Non-goals

* Rewriting `libauksapi` or the wire protocol beyond the new message(s)
  needed for Phase 4.
* PAM module changes (it only does ADD; unaffected).
* Supporting Slurm older than the version pinned in CI.

## Open questions for Bryce

1. Target Slurm version(s) to support — determines the CLONE_VM answer and
   which `spank_*` helpers are available.
2. Is `job_container/tmpfs` in use? It changes the priority of moving
   ccache creation into `user_init`.
3. Default ccache type on compute nodes today (FILE in `/tmp`, KEYRING, KCM,
   `/run/user`)? Drives the `krb5_cc_new_unique` policy in Phase 1.
4. Is Phase 4 in scope for this effort, or is the plugin rewrite (0-2) the
   deliverable with A1 tracked separately?

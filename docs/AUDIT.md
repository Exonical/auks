# AUKS audit

Scope: the Slurm SPANK plugin (`src/plugins/slurm/slurm-spank-auks.c`, 930
lines) and the parts of `libauksapi` / `auksd` it depends on for correctness
and security. Method: static reading of the tree at commit `360f898`, a local
build, and cross-checking against the Slurm SPANK contract. Nothing was run
against a live Slurm; every claim that depends on Slurm runtime behaviour is
marked **[hypothesis]** and names the check that would settle it.

Line numbers refer to the current tree. Severity is relative to a cluster
where auksd holds every user's TGT: **High** = credential exposure or
privilege boundary, **Medium** = credential loss / job failure / wrong
behaviour in realistic configs, **Low** = hygiene.

Summary of the position: the design is sound for what it is (Kerberos-
authenticated stream, server-side ownership derivation, addressless
forwarding), and no remotely exploitable memory-safety bug was found in the
reviewed paths. The SPANK plugin, however, is a 2009-era design that leaks
process state across Slurm's lifecycle, does privileged work in the wrong
hooks, has several latent bugs, and has zero test coverage. Those are the
drivers for the overhaul plan.

---

## A. SPANK plugin findings

### A1. Compute nodes are `admin`: any node can pull any user's TGT — **High (design)**

Evidence: `auksd_req.c` `_auksd_get_req` — with role `admin` the uid in the
request is served unconditionally; `HOWTO` and `fixtures/auks.acl` grant
`admin` to `host/*` principals because `slurmstepd` fetches by uid before it
knows anything but the uid.

Impact: compromise of one compute node (or of `/tmp/krb5cc_0` on it) yields
every active user's forwardable TGT via a single `auks -g -u <uid>` per uid.
There is no binding between the GET and a Slurm job/step.

This is inherent to the current protocol and cannot be fixed inside the
plugin alone; it is the main architectural item for the overhaul plan
(job-scoped authorisation, or a token minted by `slurmctld`).

### A2. Fetch and store happen in `slurm_spank_init` as root — **Medium**

`slurm_spank_init` → `spank_auks_remote_init` (l.200-210, 471-660) runs in
`slurmstepd` before `spank_init_post_opt`, before any job container /
namespace setup, and before privilege drop. The plugin compensates with
per-thread raw `setresuid/setresgid` syscalls (l.175-190) so only the calling
thread becomes the user while the rest of `slurmstepd` stays root.

Consequences:

* The ccache is created outside the job's namespaces/cgroup if a
  `job_container` plugin (tmpfs `/tmp`) is configured; with `job_container/
  tmpfs` a `/tmp` FILE ccache created here is **not** the `/tmp` the tasks
  see. **[hypothesis]** — verify with `job_container/tmpfs` + `force_file_
  ccache` or a `FILE:/tmp/...` default ccache type.
* `krb5_cc_new_unique` (l.574) picks the ccache *type* from root's default
  ccache (`auks_krb5_cred.c`), not the user's `krb5.conf` policy. If root
  uses `KEYRING:persistent:0` the user cache becomes `KEYRING:persistent:0:…`
  resolved under a thread whose euid is the user. Whether the kernel keyring
  ends up owned by the user or root depends on libkrb5's use of the thread
  fsuid. **[hypothesis]** — test on a KEYRING-default host.
* `--auks=` remote option callbacks have not run yet, so the remote mode is
  taken from the job env `SLURM_SPANK_AUKS` or `default=` (l.781-808). This
  works only because the client sets the env var; a job whose environment
  is not propagated (`--export=NONE`) silently falls back to `default=`.
* Errors here return `-1` from `slurm_spank_init`. With `required` the step
  fails (good for kerberised workloads); with `optional` — the configuration
  the `HOWTO` recommends — the error is logged and the step runs without a
  ticket, which the user only discovers when the job fails later.

### A3. Renewer is a `fork()` from `slurmstepd` with inherited fds and no supervision — **Medium**

`slurm_spank_user_init` (l.301-368) forks and `execv`s `$BINDIR/auks -R loop`.

* No `closefrom`/`CLOEXEC` sweep: every `slurmstepd` fd not already
  `O_CLOEXEC` (sockets to `slurmd`, I/O pipes, cgroup fds) is inherited by a
  long-lived process running as the user. `slurmstepd` itself sets
  `FD_CLOEXEC` on most of its fds, so the practical leak is limited to what
  it misses **[hypothesis]** — verify with `ls -l /proc/<renewer>/fd`.
* `renewer_pid` is a plain global (l.149) written in `user_init` and read
  in `task_exit`. **Settled** against `src/slurmd/slurmstepd/mgr.c`:
  in 20.11.9 (l.1772) and 23.02.7 (l.1887) `spank_user()` is called
  directly in the `slurmstepd` process after `drop_privileges` — no child
  at all, so the global is simply shared. From 24.11 (`_run_spank_func`,
  l.1012-1110) it is still in-process by default; only with
  `SlurmdParameters=contain_spank` is it run in a `clone(CLONE_VM|SIGCHLD)`
  child (`_spank_user_child`), which shares memory, so the write is
  visible either way. Two consequences remain: (a) under `contain_spank`
  the renewer's parent is the short-lived clone child, so `slurmstepd`'s
  `waitpid(renewer_pid)` (l.288) fails with `ECHILD` after `kill()` — the
  kill still lands but the renewer is never reaped by us; (b) the plugin
  still relies on an implementation detail that Slurm's comment in
  `_run_spank_func` explicitly calls out as a constraint they chose to
  honour, not a documented guarantee.
* Renewer is killed only when `exited_tasks == local_task_count` in
  `slurm_spank_task_exit` (l.263). If the step is torn down without a
  `task_exit` per task (node drain, `slurmstepd` crash, OOM-kill of
  `slurmstepd`) the renewer is orphaned; it will then keep GETting from
  auksd and renewing a ccache that `slurm_spank_exit` may never destroy.
  cgroup teardown by `slurmd` kills it in `proctrack/cgroup` setups
  **[hypothesis]**, but the ccache stays on disk.
* No `SIGTERM` handler in `auks -R loop`; kill is followed by a blocking
  `waitpid` (l.288) in the `slurmstepd` main thread with no timeout.
* If the "cred found in ccache" early exit (l.564-568) is taken,
  `auks_credcache` stays `NULL`, yet `user_init` still forks a renewer
  (l.323) whose `KRB5CCNAME` is *`slurmstepd`'s*, not the job's. It renews
  whatever root's env points at (or nothing) as the user. **Confirmed by
  reading**; harmless but wrong.
* `exited_tasks` is `volatile uint32_t` (l.150) incremented from
  `task_exit`; it is safe only because Slurm calls `task_exit` serially from
  one thread. It is never reset, so a plugin instance reused for a second
  step in the same `slurmstepd` (not something Slurm does today) would
  never reach the equality.

### A4. `force_file_ccache` path: inverted `umask`, defeated `mkstemp` — **Low**

l.588: `umask(S_IRUSR | S_IWUSR)` *masks out* owner r/w, so `mkstemp`
creates a 0000 file. `auks_cred_store` then resolves the bare path as a
`FILE:` ccache; MIT `fcc_initialize` unlinks and recreates the file
(**[hypothesis]** on libkrb5 internals — the visible effect is that the
plugin works today), so the reservation `mkstemp` was meant to provide is
lost and the code is correct by accident. The intended value is `umask(077)`
— or, better, drop this code path (see plan).

### A5. Format-string argument missing — **Low (confirmed bug)**

l.776: `xinfo("user '%u' not allowed to do auks stuff by conf");` has no
argument for `%u` — undefined behaviour, prints garbage (only when
`minimum_uid` is configured and a uid is below it).

### A6. Option/env parsing is loose — **Low**

* `_auks_opt_process` (l.820-836): `strncmp("no", optarg, 2)` accepts
  `--auks=nothing`; `--auks=yes` inside an allocation whose env already has
  `SLURM_SPANK_AUKS=done` is silently overridden by the env
  (`_spank_auks_get_current_mode` consults env before `auks_mode`).
* `spank_getenv(sp, "SLURM_SPANK_AUKS", buf, 5)` (l.782): any value ≥ 5
  chars makes `spank_getenv` fail and the env is treated as unset.
* Client sets `SLURM_SPANK_AUKS` with `overwrite=0` (l.433, 449, 457): a
  pre-existing `SLURM_SPANK_AUKS=yes` in the user's shell survives a failed
  forward, so `slurmstepd` will try a GET that fails.
* `_parse_plugstack_conf` (l.842-890) uses `strncmp(elt, "conf=", 5)`-style
  prefix matching with hard-coded lengths; unknown args are silently
  ignored (no error on typos such as `spankstackcreds=yes`).

### A7. `spankstackcred=yes` mutates `slurmstepd`'s own environment — **Low**

l.629 `setenv("KRB5CCNAME", …)` in the root process, so that later SPANK
plugins (e.g. for Lustre/NFS) see the ticket. It is never unset. Any later
code in `slurmstepd` that runs as root with libkrb5 (including the next
step's `auks_api_get_auks_cred` if `hostcredcache` is not set) will now use
the *user's* ccache and fail authentication as `host/…`. Today each step has
its own `slurmstepd`, so this is only a hazard, not a live bug.

### A8. `sync=yes|all` calls global `sync()` from `slurmstepd` — **Low**

`_sync_fs` (l.909-929) flushes every mounted filesystem on the node, once per
step end and once per exit, to make sure the ccache reaches a shared
filesystem before it is destroyed. On a node with busy local disks this
stalls `slurmstepd` for seconds. `fsync()` on the ccache file, or `syncfs()`
on its fd, is the targeted equivalent.

### A9. Global mutable state throughout — **Maintainability**

Twelve file-scope globals (l.121-150) carry configuration, the ccache path,
the renewer pid and the task counter between hooks. Nothing is
re-initialised except `auks_credcache` (l.509). Error paths free
`auks_conf_file`/`auks_hostcredcache_file` in `remote_exit` (l.671-678) but
`auks_sync_mode` only on some paths (l.744). There is no `spank_context`-
keyed struct, which is what makes the `CLONE_VM` question in A3 matter.

### A10. Not covered by any test — **Maintainability**

`tests/simple.bats` exercises the CLI only. `.gitlab-ci.yml`'s test job is
commented out. The plugin has never been built against Slurm in CI (`--with-
slurm` is not passed in `.travis.yml`/Dockerfile). Behavioural regressions in
the plugin are invisible until a cluster upgrade.

---

## B. Library / daemon findings relevant to the plugin

### B1. ACL `host` field is dead — **Medium (misleading security control)**

`auksd_req.c` calls `auks_acl_get_role(&acl, principal, "*", &role)`; the
host argument is the literal `"*"`. `_auks_acl_rule_check_host`
(`auks_acl.c` l.431-476) compares that string against the rule's host and
its resolved IPv4 addresses, so a rule with `host = compute01;` matches
**nothing** and a rule with `host = *;` matches everything. Fails closed,
but `auks.acl(5)` and `etc/auks.acl.example` document host restriction as
working. Additionally `getaddrinfo` is called for every non-`*` rule on
every request (DNS on the auth path) and only `AF_INET` is considered.

### B2. Unanchored principal regexes — **Medium (operator footgun)**

Rule principals are compiled with `REG_EXTENDED` and matched with
`regexec` anywhere in the string (`auks_acl.c` l.409-411). `principal =
admin@EXAMPLE.COM;` grants admin to `notadmin@EXAMPLE.COM`; `.` matches any
char. The shipped examples anchor with `^…$` (mostly — `fixtures/auks.acl`'s
guest rule `^host/.*@EXAMPLE.COM` lacks `$`). The parser should anchor
implicitly or reject unanchored rules. Regex is also recompiled per request.

### B3. Cross-uid trust rests on `krb5_aname_to_localname` + `getpwnam_r` on the auksd host — **Info**

`auks_cred.c` derives `uid` server-side from the credential's client
principal. This is correct and is the property that stops user A from
ADDing a cred that is filed under B's uid. It requires auksd's `krb5.conf`
`auth_to_local` and its passwd database to agree with the compute nodes';
a mismatch silently files creds under the wrong uid.

### B4. Repository persistence — **Info**

`CacheDir/aukscc_<uid>` FILE ccaches hold every user's TGT on the management
node, 0600 root, in a 0700 directory (RPM `%attr`). The Debian/manual install
path has no equivalent guarantee — `make install` does not create
`CacheDir`. The cleaner (`auks_cred_repo.c` l.731-760) removes expired creds
every `CleanDelay` s; nothing removes a cred when its jobs end, so TGTs sit
in the repo for their full renewable life (typically 7 d) after the last job.

### B5. Protocol robustness — **Low**

* auksd reads with `krb5_read_message` + `krb5_rd_priv`
  (`auks_krb5_stream.c` l.619-630), so nothing is parsed pre-auth. After
  auth, `auks_buffer` unpacks lengths and `malloc`s them without an upper
  bound; `xstream_receive_msg_timeout` (`xstream.c` l.749-753) likewise
  `malloc(ntohl(len))` unchecked, but it is only used by the CLI
  `send`/`receive` path. A trusted peer can force large allocations; not
  exploitable pre-auth.
* `LIST` and `CRED_DUMP` are half-implemented (`LIST` replies `PING`).
* `ReplayCache = no` and `NAT = yes` are documented knobs that weaken
  `krb5_rd_priv` protections (replay, address binding). Defaults are safe.

### B6. `HelperScript` runs synchronously as the user with inherited environment — **Low**

`auks_api_run_helper` (`auks_api.c`) `fork`s, `setresgid/uid`, `setenv
KRB5CCNAME`, `execv`, and the parent `waitpid`s with no timeout — from inside
`slurm_spank_init` (A2). A hanging helper hangs step launch. The script path
is silently dropped if not executable rather than rejected at config time.

### B7. Build/packaging — **Info**

* `src/plugins/pam/Makefile.am` hard-codes `/usr/lib64/security`.
* `auks.spec.in` is RHEL-shaped; no Debian packaging.
* `configure` defaults `--enable-tirpc`; the code still includes `rpc/`
  headers through `auks_buffer` for `xdr`-era compatibility.

---

## C. What was checked and found fine

* Authentication: mutual `krb5_sendauth`/`recvauth`, sequence numbers,
  per-message `mk_priv`/`rd_priv`; unauthenticated peers get no dispatch.
* ADD authorisation: non-admin must present a cred whose client principal
  equals the authenticated principal, and the cred must be addressless.
* GET/REMOVE for role `user`: compares the *stored* principal, so knowing
  another uid gains nothing.
* Client-side uid is never trusted for ownership.
* No format-string sinks fed by network data; buffer sizes for principal
  strings are bounded (`AUKS_PRINCIPAL_MAX_LENGTH`).
* Cross-realm and addressless handling go through the KDC (TGS requests),
  not by editing tickets.

## D. Verification still owed

| Item | How |
|---|---|
| ~~A3 `CLONE_VM` vs `fork` for `spank_user_init`~~ | done — in-process (20.11, 23.02, 24.11 default) or `CLONE_VM` (24.11 `contain_spank`); see A3 |
| A2 namespaces with `job_container/tmpfs` | compose test with a `job_container.conf`; compare ccache path visibility from a task |
| A2 KEYRING ownership | `keyctl show` from a task on a `KEYRING:`-default host |
| A3 fd leak | `ls -l /proc/<renewer>/fd` during a step |
| A4 libkrb5 recreate behaviour | `strace -f` the store under `force_file_ccache` |

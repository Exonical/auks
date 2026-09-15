# AUKS architecture

AUKS (Aside Utility for Kerberos Support) forwards a user's Kerberos TGT from
the node where a job is submitted to the nodes where it runs, and keeps it
renewed for the life of the job. It was written at CEA for Slurm; this
repository is a fork of `cea-hpc/auks` (last upstream commit 2024-07).

This document describes what is in the tree today. It does not make
recommendations; see `AUDIT.md` and `SPANK_OVERHAUL_PLAN.md` for that.

## 1. Components

| Component | Source | Installed as | Runs on | Runs as |
|---|---|---|---|---|
| `libauksapi` | `src/api/auks/` | `$(libdir)/libauksapi.so`, headers in `$(includedir)/auks` | everywhere | caller |
| `auks` CLI | `src/auks/auks.c` | `$(bindir)/auks` | login, compute (as renewer) | user |
| `auksd` | `src/auksd/auksd.c`, `auksd_req.c` | `$(sbindir)/auksd` | management node | root |
| `auksdrenewer` | `src/auksd/auksdrenewer.c` | `$(sbindir)/auksdrenewer` | management node | root |
| `aukspriv` | `src/auksd/aukspriv` (bash) | `$(sbindir)/aukspriv` | management + compute | root |
| Slurm SPANK plugin | `src/plugins/slurm/slurm-spank-auks.c` | `$(libdir)/slurm/auks.so` | login + compute | srun/sbatch (user), slurmstepd (root) |
| PAM module | `src/plugins/pam/pam_auks.c` | `/usr/lib64/security/pam_auks.so` (hard-coded path) | login | root (PAM session) |
| confparse | `src/api/confparse/` (flex/bison) | static, not installed | – | – |
| xternal | `src/api/xternal/` | static, not installed | – | – |

Supporting: `etc/` (example `auks.conf`/`auks.acl`, systemd units, SysV init,
logrotate), `doc/man/`, `auks.spec.in` (RPM: `auks`, `auks-devel`,
`auks-slurm`, `auks-pam`), `Dockerfile` + `compose.yaml` + `fixtures/` +
`tests/simple.bats` (integration test rig with a real MIT KDC).

`src/plugins/slurm/auks.so.8` and `src/plugins/pam/pam_auks.so.8` are troff
man pages despite the `.so` in their names, not binaries.

## 2. End-to-end flow (Slurm)

```
 login node (user)                 management node (root)             compute node
 ---------------------             ----------------------             --------------------------------
 kinit -> FILE:/tmp/krb5cc_U       aukspriv: kinit -k host/mngt        aukspriv: kinit -k host/compute
                                    -> /tmp/krb5cc_0 (root)              -> /tmp/krb5cc_0 (root)
 srun/sbatch --auks=yes
   [spank init_post_opt, LOCAL]
   auks_api_add_cred(NULL)
     read TGT from default cc
     make addressless (TGS fwd)  --ADD--> auksd
     (opt) cross-realm TGT                 authn: krb5_recvauth
   setenv SLURM_SPANK_AUKS=done            ACL role(principal) -> user
                                           cred.principal == authn principal ?
                                           uid = getpwnam(aname_to_localname)
                                           repo[uid] = cred ; CacheDir/aukscc_<uid>
                                                                          slurmstepd [spank init, REMOTE, root]
                                                                            auks_api_get_auks_cred(uid) <--GET-- (as host/compute via /tmp/krb5cc_0)
                                           role(host/compute) = admin -> OK
                                                                            seteuid(user) [this thread only]
                                                                            krb5_cc_new_unique(default type) -> CC
                                                                            store cred in CC ; krb5_cc_switch(CC)
                                                                            spank_setenv KRB5CCNAME=CC
                                                                            run HelperScript as user (sync)
                                                                          [spank user_init, as user]
                                                                            fork+exec `auks -R loop` (KRB5CCNAME=CC)
                                                                              every Delay s: if lifetime < MinLifeTime:
                                                                                GET uid from auksd, else renew at KDC
                                                                                store into CC ; run HelperScript
 auksdrenewer (mgmt): every Delay s
   DUMP all; for each cred near expiry: renew at KDC (addressless) ; ADD back
                                                                          [spank task_exit, last task]
                                                                            sync() (if sync=yes) ; kill renewer
                                                                          [spank exit]
                                                                            krb5_cc_destroy(CC)
```

Key properties of the design:

* The **object forwarded is the user's TGT**, serialised with
  `krb5_mk_ncred` and re-serialised addressless via a TGS request
  (`auks_krb5_cred_deladdr_buffer`). auksd stores the serialised blob and
  re-writes it as a FILE ccache `CacheDir/aukscc_<uid>` for persistence across
  restarts.
* **auksd trusts host principals as admins.** Compute nodes fetch by uid using
  their `host/` keytab-derived ticket; the ACL grants them `admin`, i.e. the
  right to fetch any uid's TGT. There is no job-scoped authorisation.
* **Ownership is derived server side** from the credential's client principal
  (`krb5_aname_to_localname` + `getpwnam_r`), never from a uid sent by the
  client. The requesting principal must equal the credential principal unless
  the requester is admin.
* Renewal is two-tier: `auksdrenewer` keeps the repository copy fresh; a
  per-step `auks -R loop` on each compute node refreshes the step ccache,
  preferring a fresh GET from auksd and falling back to KDC renewal.

## 3. Library layers (`libauksapi`)

```
auks_api.[ch]        high-level client ops: init/close, ping, add, get, remove, dump,
                     renew (once/loop), send/receive (ASCII), run_helper
  auks_engine.[ch]   client config (auks.conf: common + api + renewer)
  auksd_engine.c     daemon config (common + auksd)
  auks_message.[ch]  request/reply framing: int type + auks_buffer
  auks_buffer.[ch]   htonl-packed ints, uid as int, raw bytes
  auks_cred.[ch]     auks_cred_t = {info{principal,uid,start,end,renew_till,addressless,crossrealm}, data[], length}
                     extract/store (via krb5_cred), renew_test, pack/unpack
  auks_krb5_cred.[ch] all libkrb5 work: get/store TGT, renew, deladdr, cross_realm,
                     cc_new_unique, cc_switch, cc_destroy
  auks_krb5_stream.[ch] krb5_sendauth/recvauth over a TCP socket, then
                     krb5_mk_priv/rd_priv per message (KRB5_AUTH_CONTEXT_DO_SEQUENCE);
                     flags: NAT_TRAVERSAL (dummy addresses), NO_RCACHE
  auks_cred_repo.[ch] auksd in-memory index (xlibrary) + on-disk FILE ccaches
  auks_acl.[ch]      auks.acl rules {principal regex, host, role}
  auks_error.[ch]    error codes and auks_strerror
xternal/             xstream (TCP connect/send/recv with poll timeouts, 4-byte length prefix),
                     xqueue (socket queue), xlibrary (hash of items), xfreelist, xlogger
confparse/           generated lex/yacc for the `block { Key = value ; }` syntax
```

### Wire protocol

Per connection: TCP connect → `krb5_sendauth`/`krb5_recvauth` (mutual, subkey)
→ N × (`krb5_mk_priv` framed by `krb5_write_message`) → client sends CLOSE and
disconnects. Message body = `uint32 type` then optional `uint32 len` +
payload (all `htonl`).

| Type | Req | Rep | Payload | Gate in auksd |
|---|---|---|---|---|
| PING | 0 | 20 | – | any known role |
| LIST | 1 | (22, unimplemented: replies PING) | – | – |
| ADD | 2 | 23 | serialised cred | non-admin: cred.principal == authn principal; cred must be addressless |
| GET | 3 | 24 | uid (int) | admin: any; user: repo[uid].principal == authn principal; guest: denied |
| REMOVE | 4 | 25 | uid | same as GET |
| CLOSE | 5 | – | – | ends session |
| DUMP | 6 | 26 | – | admin only; returns count + creds |
| CRED_DUMP | 7 | – | – | not handled |
| ERROR | – | 21 | – | – |

Retries: `Retries` × (primary, secondary) with `Timeout` s connect timeout and
`Delay` s between rounds (`auks_api_request`).

## 4. auksd

* Dispatcher thread `accept()`s and pushes sockets onto an `xqueue`;
  `Workers` threads pop, run `auksd_process_req`, close. One extra thread is
  the repository cleaner (`CleanDelay`), which drops creds whose `endtime` or
  `renew_till` has passed.
* Authentication: `krb5_recvauth` against `PrimaryKeytab`/`PrimaryPrincipal`
  (or Secondary when started with that role). Replay cache can be disabled
  (`ReplayCache = no`).
* Authorisation: `auks_acl_get_role(acl, principal, "*")` — the host argument
  is always the literal `"*"`.
* Storage: `CacheDir/aukscc_<uid>` FILE ccaches, loaded at startup, written on
  ADD, unlinked on REMOVE/clean. Permissions are whatever libkrb5 gives a
  FILE ccache created by root (0600) inside the 0700 `CacheDir` from the spec.

## 5. Configuration

`auks.conf` (`SYSCONFDIR/auks.conf`, `AUKS_CONF`/`AUKSD_CONF` env override,
`-f` on CLIs, `conf=` in plugstack). Blocks and keys with code defaults
(`src/api/auks/auks_engine.h`):

* `common`: `PrimaryHost` (localhost) / `PrimaryAddress` / `PrimaryPort`
  (12345) / `PrimaryPrincipal` (""), `Secondary*` (same defaults),
  `CrossRealm` (""), `Retries` 3, `Timeout` 10, `Delay` 10, `NAT` no.
* `api`: `LogFile` `/tmp/auksapi.log`, `LogLevel` 0, `UseSyslog`, `DebugFile`,
  `DebugLevel` 0, `HelperScript` (unset; silently dropped if not executable).
* `auksd`: `PrimaryKeytab`/`SecondaryKeytab` (`/etc/auks/auks.keytab`),
  `CacheDir` (`LOCALSTATEDIR/cache/auks`), `ACLFile` (`SYSCONFDIR/auks.acl`),
  `LogFile` `/var/log/auksd.log`, `LogLevel` 1, `DebugFile`, `DebugLevel`,
  `Workers` 10, `QueueSize` 50, `RepoSize` 500, `CleanDelay` 300,
  `ReplayCache` yes.
* `renewer` (read by `auksdrenewer` and by `auks -R`): `LogFile`, `LogLevel`,
  `DebugFile`, `DebugLevel`, `Delay` 60, `MinLifeTime` 300. Key lookup is
  case-insensitive (`strncasecmp` in `config_parsing.c`).

`auks.acl`: ordered `rule { principal = <POSIX ERE or *> ; host = <* | name |
IPv4> ; role = guest|user|admin ; }`; first match wins; no match → `unknown`
→ connection refused.

`aukspriv` (bash): loops `kinit -k -t $AUKS_PRIV_KEYTAB` every
`AUKS_PRIV_RENEW_INT` s into root's default ccache so that `slurmstepd` (and
`auksd`/`auksdrenewer`) always have a host ticket. Configured through
`/etc/sysconfig/aukspriv` env vars.

## 6. Slurm SPANK plugin (`auks.so`)

### plugstack.conf arguments (`_parse_plugstack_conf`)

| Arg | Effect |
|---|---|
| `conf=PATH` | auks.conf path |
| `default=enabled\|disabled` | mode when neither `--auks` nor `SLURM_SPANK_AUKS` is given (default disabled) |
| `spankstackcred=yes` | also `setenv KRB5CCNAME` in slurmstepd's own environment so later SPANK plugins see the ticket |
| `enforced` | on the client, a missing ccache is an error (returns non-zero) instead of silently disabling |
| `force_file_ccache` | use the legacy `/tmp/krb5cc_<uid>_<jobid>_XXXXXX` mkstemp path instead of `krb5_cc_new_unique` |
| `no_cc_switch` | do not `krb5_cc_switch` the new cache into the collection |
| `minimum_uid=N` | uids below N never do auks |
| `hostcredcache=PATH` | ccache slurmstepd uses to authenticate to auksd (default: libkrb5 default for root) |
| `sync=yes\|all` | call `sync()` before killing the renewer / destroying the ccache |

User-facing: `--auks=yes|no|done` on `srun`/`sbatch`/`salloc`, and the
`SLURM_SPANK_AUKS` env var (`yes`/`no`/`done`). `done` means "credential is
already in auksd, skip the client ADD".

### Callback map

| Slurm hook | Context | What the plugin does |
|---|---|---|
| `slurm_spank_init` | all | register `--auks`; parse plugstack args; if remote → `spank_auks_remote_init` (fetch + store ticket, **before** remote option callbacks run) |
| `_auks_opt_process` | option cb | set `auks_mode`; `done` also `setenv SLURM_SPANK_AUKS=done` |
| `slurm_spank_init_post_opt` | allocator/local | `spank_auks_local_user_init`: `auks_api_add_cred`; `setenv SLURM_SPANK_AUKS=done\|no` (propagates to the job env) |
| `slurm_spank_user_init` | remote, euid=user (Slurm runs this in a `clone(CLONE_VM)` child) | `fork`+`execv $BINDIR/auks -R loop` with `KRB5CCNAME` set; child does `setresuid/gid` to euid |
| `slurm_spank_task_exit` | remote, per task | when `exited_tasks == local_task_count`: seteuid(user), `_sync_fs`, `SIGTERM` + `waitpid` renewer |
| `slurm_spank_exit` | remote | `spank_auks_remote_exit`: seteuid(user), `_sync_fs`, `krb5_cc_destroy(ccache)`; free config strings |

`spank_auks_remote_init` sequence: read `S_JOB_ID/UID/GID` → `auks_api_init`
→ (opt) `auks_api_set_ccache(hostcredcache)` → `auks_api_get_auks_cred(uid)`
as root → raw `setresgid/setresuid` syscalls to switch **only this thread's**
euid/egid to the user → if `KRB5CCNAME` from the job env already yields a
readable TGT, stop → else `krb5_cc_new_unique` (type of root's default cc) or
mkstemp file → `auks_cred_store` → `krb5_cc_switch` → `spank_setenv
KRB5CCNAME` → run `HelperScript` synchronously → restore euid/egid.

The plugin's persistent state is a handful of file-scope globals
(`auks_credcache`, `renewer_pid`, `exited_tasks`, parsed options), one
`auks_engine_t`, and the `SLURM_SPANK_AUKS`/`KRB5CCNAME` variables in the
job environment.

## 7. PAM module

`pam_sm_open_session`: for non-root users, seteuid/egid to the user, read
`AUKS_CONF` and `KRB5CCNAME` from the PAM env, `auks_api_add_cred` (i.e. push
the login TGT to auksd at login time), restore ids. `close_session` is a
no-op. Options: `syslog`, `quiet`.

## 8. Build and test

* Autotools: `autoreconf -i && ./configure [--with-slurm[=PATH]] [--with-pam]
  [--enable-tirpc] && make`. Requires krb5 (pkg-config), flex, bison,
  libtirpc (default on). Verified to build on Ubuntu with
  `libkrb5-dev libtirpc-dev flex bison`.
* `make rpm` builds the four RPMs; `.gitlab-ci.yml` does that; `.travis.yml`
  does a plain build on amd64/arm64.
* `compose.yaml` brings up `kdc`, `auks_server`, `auks_client` (AlmaLinux 8)
  and `tests/simple.bats` exercises ping/add/get/renew/remove/dump/send/
  receive, ACL denials, cross-realm, and helper-script behaviour through the
  `auks` CLI. **The SPANK plugin is not covered by any test.**

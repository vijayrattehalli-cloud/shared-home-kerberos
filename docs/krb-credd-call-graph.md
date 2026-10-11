# krb-credd call graph

Every function call in the krb-credd data flow (version 2.3.0). Each diagram follows one path through the code; labels give `file:line` of the function definition (credd.py unless another file is named). An interactive version with the same diagrams is in [`krb-credd-call-graph.html`](krb-credd-call-graph.html).

**Colour key:** blue = krb-get (user side) · green = credd.py (daemon) · amber = _krb.py (Kerberos helpers) · red = external program · purple = file / socket · grey = decision.

Contents: [Overview: who calls whom](#overview) · [krb-get, the client](#client) · [Daemon start-up](#startup) · [Handling a socket request](#request) · [ensure(): decide whether to mint and install](#ensure) · [Minting: broker TGT, S4U, validation](#mint) · [One GET, end to end (first login, nothing cached)](#sequence) · [Background refresh thread](#refresh) · [krb-credd --check [--user NAME]](#check)

<a id="overview"></a>

## 0. Overview: who calls whom

```mermaid
flowchart LR
  classDef cli fill:#cfe0f7,stroke:#4a78b5,color:#111
  classDef dmn fill:#d9ecd9,stroke:#4c8a4c,color:#111
  classDef krb fill:#f3e3c3,stroke:#b4873a,color:#111
  classDef ext fill:#f2d0cf,stroke:#b5524f,color:#111
  classDef file fill:#e4e0f0,stroke:#6e62a3,color:#111

  shell["login shell<br/>profile.d-krb-hpc.sh"]:::ext --> get["krb-get<br/>get.main"]:::cli
  prolog["Slurm TaskProlog<br/>taskprolog.krb.sh"]:::ext --> get
  get -- "GET / STATUS" --> sock[("/run/krb-hpc/credd.sock")]:::file
  sock --> handler["Handler.handle<br/>credd.py:643"]:::dmn
  handler --> tm["TicketManager<br/>ensure / status"]:::dmn
  refresh["refresh thread<br/>refresh_loop :617"]:::dmn --> tm
  tm --> krb["Krb5 helpers<br/>_krb.py"]:::krb
  krb --> kinit["kinit"]:::ext
  krb --> klist["klist"]:::ext
  krb --> kvno["kvno"]:::ext
  kinit & kvno --> ad["Active Directory KDC"]:::ext
  tm --> setpriv["setpriv --reuid=user"]:::ext --> inst["krb-install-ccache<br/>install_ccache.main"]:::cli
  refresh --> squeue["squeue"]:::ext
  krb --- bcc[("broker.cc<br/>broker TGT")]:::file
  tm --- master[("state_dir/uid.cc<br/>master copy")]:::file
  inst --> home[("~/.krb5cc_hpc<br/>user's cache")]:::file
```

- Two entry points drive all minting: a user's `krb-get` request, and the daemon's own refresh thread.
- Only `kinit` and `kvno` talk to AD. `klist` only reads local cache files.
- The daemon is root; the only code that writes into a home directory runs as the user under `setpriv`.

<a id="client"></a>

## 1. krb-get, the client

*src/krbhpc/get.py*

```mermaid
flowchart TD
  classDef cli fill:#cfe0f7,stroke:#4a78b5,color:#111
  classDef dec fill:#ececec,stroke:#888,color:#111
  classDef file fill:#e4e0f0,stroke:#6e62a3,color:#111

  m["main :67<br/>read KRB_HPC_SOCKET, KRB_HPC_TIMEOUT"]:::cli --> a{"argv?"}:::dec
  a -- "--status" --> st["_status :45"]:::cli
  a -- "none" --> askg["_ask :22<br/>send 'GET'"]:::cli
  a -- "other" --> use["print usage, exit 2"]:::cli
  st --> asks["_ask :22<br/>send 'STATUS'"]:::cli
  askg & asks --> sock[("AF_UNIX connect<br/>credd.sock")]:::file
  st --> when["_when :31<br/>format expiry / retry times"]:::cli
  askg --> r{"reply"}:::dec
  r -- "OK path" --> out["print export KRB5CCNAME=FILE:path<br/>shell evals it, exit 0"]:::cli
  r -- "ERR msg" --> err["print msg to stderr, exit 1"]:::cli
  r -- "socket error" --> e2["exit 2"]:::cli
```

- `krb-get` sends nothing about who the user is. The daemon reads the caller's UID from the socket with `SO_PEERCRED`.
- The path is quoted with `shlex.quote` because the shell evaluates the output.

<a id="startup"></a>

## 2. Daemon start-up

*credd.py main :797*

```mermaid
flowchart TD
  classDef dmn fill:#d9ecd9,stroke:#4c8a4c,color:#111
  classDef krb fill:#f3e3c3,stroke:#b4873a,color:#111
  classDef ext fill:#f2d0cf,stroke:#b5524f,color:#111
  classDef dec fill:#ececec,stroke:#888,color:#111
  classDef file fill:#e4e0f0,stroke:#6e62a3,color:#111

  main["main :797<br/>must be root; umask 077"]:::dmn --> hard["_harden_process :778<br/>RLIMIT_CORE=0, PR_SET_DUMPABLE=0"]:::dmn
  hard --> c{"--check?"}:::dec
  c -- yes --> chk["check :696<br/>see diagram 8"]:::dmn
  c -- no --> load["Config.load :143"]:::dmn
  load --> as1["_assert_secure :92<br/>config, uidmap root-owned"]:::dmn
  load --> dur["duration_seconds _krb:28"]:::krb
  load --> nt["_name_type :238"]:::dmn
  load --> uidmin["_login_defs_uid_min :224<br/>min_uid default"]:::dmn
  load --> um["UidMap.__init__ :259"]:::dmn
  um --> tmi["TicketManager.__init__ :293"]:::dmn
  tmi --> k5["Krb5.__init__ _krb:286<br/>tool paths, -U or -I"]:::krb
  tmi --> as2["_assert_secure :92<br/>keytab, state dir, helper, tools"]:::dmn
  tmi --> seed["_seed_active :340<br/>users with existing masters"]:::dmn
  tmi --> ver["Krb5.version _krb:319"]:::krb
  ver --> run1["Krb5.run _krb:311"]:::krb --> kl["klist -V"]:::ext
  ver --> pmv["parse_mit_version _krb:220<br/>MIT 1.19 or newer"]:::krb
  ver --> prin["UidMap.principal :265<br/>load map, warn on uid below min_uid"]:::dmn
  prin --> eb["_ensure_broker :363<br/>get broker TGT now; failure only warns"]:::dmn
  eb --> srv["Server(credd.sock, Handler)<br/>chmod 0666"]:::dmn
  srv --> thr["Thread: refresh_loop :617"]:::dmn
  srv --> sf["serve_forever<br/>one thread per connection"]:::dmn
  sf --> h["Handler.handle :643"]:::dmn
```

- A bad config, insecure file permissions or a non-MIT `klist` stop the daemon with one clear line.
- The broker TGT is fetched at start-up so a bad keytab shows in the log at once. See diagram 5 for what `_ensure_broker` does.

<a id="request"></a>

## 3. Handling a socket request

*credd.py Handler.handle :643*

```mermaid
flowchart TD
  classDef dmn fill:#d9ecd9,stroke:#4c8a4c,color:#111
  classDef krb fill:#f3e3c3,stroke:#b4873a,color:#111
  classDef dec fill:#ececec,stroke:#888,color:#111

  h["Handler.handle :643"]:::dmn --> sem{"semaphore<br/>MAX_CLIENTS free?"}:::dec
  sem -- no --> busy["reply ERR busy"]:::dmn
  sem -- yes --> peer["getsockopt SO_PEERCRED<br/>→ uid of caller"]:::dmn
  peer --> rq{"request line"}:::dec
  rq -- STATUS --> st["status :505<br/>never mints"]:::dmn
  st --> d1["disabled :448"]:::dmn
  st --> p1["UidMap.principal :265"]:::dmn
  st --> m1["master :356"]:::dmn
  st --> ce1["Krb5.cache_expiry _krb:363"]:::krb
  st --> okst["reply OK enrolled=… expires=… retry_at=… last_error=…"]:::dmn
  rq -- GET --> due["due_for_install :442<br/>min_reissue throttle"]:::dmn
  due --> ens["ensure :452<br/>see diagram 4"]:::dmn
  ens --> touch["touch :524<br/>mark user active"]:::dmn
  touch --> ok["reply OK /home/user/.krb5cc_hpc"]:::dmn
  rq -- other --> bad["ValueError"]:::dmn
  ens -. PermissionError .-> e1["reply ERR reason<br/>disabled, system uid, not enrolled"]:::dmn
  ens -. KrbToolError .-> e2["reply ERR USER_MESSAGES category"]:::dmn
  bad -.-> e3["reply ERR could not obtain ticket"]:::dmn
```


<a id="ensure"></a>

## 4. ensure(): decide whether to mint and install

*credd.py :452*

```mermaid
flowchart TD
  classDef dmn fill:#d9ecd9,stroke:#4c8a4c,color:#111
  classDef krb fill:#f3e3c3,stroke:#b4873a,color:#111
  classDef dec fill:#ececec,stroke:#888,color:#111
  classDef ext fill:#f2d0cf,stroke:#b5524f,color:#111

  e["ensure(uid) :452"]:::dmn --> ks{"disabled :448<br/>kill-switch file exists?"}:::dec
  ks -- yes --> pe1["PermissionError"]:::dmn
  ks -- no --> mu{"uid below min_uid?"}:::dec
  mu -- yes --> pe2["PermissionError"]:::dmn
  mu -- no --> pr{"UidMap.principal :265<br/>enrolled?"}:::dec
  pr -- no --> pe3["PermissionError"]:::dmn
  pr -- yes --> lk["per-uid lock<br/>master :356"]:::dmn
  lk --> ce["Krb5.cache_expiry _krb:363"]:::krb
  ce --> kc["_klist_cached _krb:332<br/>stat(); klist only if file changed"]:::krb
  kc --> ee["earliest_expiry _krb:71<br/>→ _parse_klist_time :42"]:::krb
  ee --> need{"missing, or expires<br/>within renew_margin?"}:::dec
  need -- no --> fc{"first use of this master<br/>since start-up?"}:::dec
  fc -- yes --> val["_validate :385<br/>see diagram 5"]:::dmn
  val -- fails --> cd
  val -- passes --> inst
  fc -- no --> inst
  need -- yes --> cd{"failure within<br/>failure_cooldown (60 s)?"}:::dec
  cd -- yes --> again["re-raise last error<br/>from_cooldown=True, no AD request"]:::dmn
  cd -- no --> mint["_mint :402<br/>see diagram 5"]:::dmn
  mint -. "KrbToolError in<br/>COOLDOWN_CATEGORIES" .-> rec["remember in _last_error"]:::dmn
  mint --> inst{"changed, forced,<br/>or _missing :629 home cache?"}:::dec
  inst -- yes --> ins["_install :426"]:::dmn
  ins --> sp["setpriv --reuid --regid<br/>--inh-caps=-all --no-new-privs"]:::ext
  sp --> ic["install_ccache.main :22<br/>runs AS THE USER"]:::ext
  ic --> wr["mkstemp, write, fsync,<br/>chmod 600, os.replace"]:::ext
  inst -- no --> done
  wr --> done["_clear_failure :538<br/>return home cache path"]:::dmn
  hc["home_ccache :359"]:::dmn -.-> inst
```

- The cooldown applies only to errors an administrator must fix: `not_delegable`, `unknown_principal`, `bad_ticket`. Timeouts and KDC outages retry at once.
- The master copy in `state_dir` is the source of truth. The home copy is reinstalled when it changes, when `due_for_install` says so, or when the user deleted it.

<a id="mint"></a>

## 5. Minting: broker TGT, S4U, validation

*credd.py _mint :402 · _krb.py*

```mermaid
flowchart TD
  classDef dmn fill:#d9ecd9,stroke:#4c8a4c,color:#111
  classDef krb fill:#f3e3c3,stroke:#b4873a,color:#111
  classDef dec fill:#ececec,stroke:#888,color:#111
  classDef ext fill:#f2d0cf,stroke:#b5524f,color:#111
  classDef file fill:#e4e0f0,stroke:#6e62a3,color:#111

  mint["_mint(principal, cc, user) :402"]:::dmn --> eb["_ensure_broker :363<br/>broker lock"]:::dmn

  subgraph B["Broker TGT"]
    eb --> kt["Krb5.klist_times _krb:359<br/>→ _klist_cached → parse_klist :54"]:::krb
    kt --> g{"1 h or more left?"}:::dec
    g -- yes --> keep["keep it"]:::dmn
    g -- no --> rn{"renewable past<br/>renew_margin?"}:::dec
    rn -- yes --> kr["kinit_renew _krb:384<br/>copy → kinit -R → os.replace"]:::krb
    kr -- failed --> kk
    rn -- no --> kk["kinit_keytab _krb:376<br/>kinit -f -r -l -k -t keytab<br/>into broker.new → os.replace"]:::krb
  end

  keep & kr & kk --> s4u["Krb5.s4u_mint _krb:406"]:::krb

  subgraph S["Constrained delegation"]
    s4u --> cp["copy broker.cc → throwaway .broker.*.cc"]:::file
    cp --> kv["Krb5.run → kvno -c copy --out-cache cc.new<br/>-U|-I user -P spn1 spn2 …"]:::ext
    kv --> ad["AD: per target<br/>S4U2Self then S4U2Proxy"]:::ext
    kv -. "non-zero exit" .-> kte["KrbToolError → classify_error :250"]:::krb
  end

  kv --> chm["chmod 600 cc.new"]:::dmn --> val["_validate :385"]:::dmn

  subgraph V["Validation (v2.3.0)"]
    val --> ins["Krb5.inspect _krb:367<br/>klist -e -f -c cc.new"]:::krb
    ins --> pkd["parse_klist_details _krb:113<br/>→ _parse_klist_time :42"]:::krb
    pkd --> vuc["validate_user_cache _krb:156<br/>→ _qualify :152"]:::krb
    vuc --> rules{"right client? no TGT? every target?<br/>AES session key? 300 s or more?"}:::dec
  end

  rules -- "fatal problem" --> fail["KrbToolError bad_ticket<br/>delete cc.new, old cache stays"]:::dmn
  rules -- "warnings only" --> log["log each warning once a day"]:::dmn
  log --> rep["os.replace cc.new → master cc"]:::file
  rep --> lm["warn once if lifetime below renew_margin"]:::dmn
```

- The S4U2Self and S4U2Proxy requests happen inside one `kvno` process, one target after another. The throwaway copy exists because `kvno` also stores the S4U2Proxy tickets in its input cache.
- `ticket_checks = warn` turns only the user-name checks into warnings. The TGT, target, AES and lifetime checks stay fatal.

<a id="sequence"></a>

## 6. One GET, end to end (first login, nothing cached)

```mermaid
sequenceDiagram
  autonumber
  participant Sh as login shell
  participant G as krb-get
  participant H as Handler.handle
  participant T as TicketManager
  participant K as Krb5 (_krb.py)
  participant X as kinit / kvno / klist
  participant AD as AD KDC
  participant I as setpriv + install helper

  Sh->>G: eval "$(krb-get)"
  G->>H: connect credd.sock, "GET"
  H->>H: SO_PEERCRED → uid
  H->>T: due_for_install(uid), ensure(uid)
  T->>T: disabled(), min_uid, UidMap.principal()
  T->>K: cache_expiry(master)
  K-->>T: None (no master yet)
  T->>T: _mint()
  T->>T: _ensure_broker()
  T->>K: klist_times(broker.cc)
  alt broker TGT stale
    K->>X: kinit -R on a copy, or kinit -k -t keytab
    X->>AD: AS-REQ / TGS renew
    AD-->>X: broker TGT
  end
  T->>K: s4u_mint(broker.cc, user, targets, cc.new)
  K->>X: kvno -c copy --out-cache cc.new -U user -P targets
  loop each target SPN
    X->>AD: S4U2Self (ticket for user to broker)
    AD-->>X: forwardable ticket
    X->>AD: S4U2Proxy (user to target, checked against msDS-AllowedToDelegateTo)
    AD-->>X: service ticket for target
  end
  X-->>K: exit 0
  T->>K: inspect(cc.new)
  K->>X: klist -e -f
  K->>K: parse_klist_details()
  T->>K: validate_user_cache()
  T->>T: os.replace(cc.new, master)
  T->>I: _install(): setpriv --reuid=user krb-install-ccache ~/.krb5cc_hpc
  I-->>T: exit 0 (atomic write as the user)
  T-->>H: home cache path
  H->>T: touch(uid)
  H-->>G: "OK /home/user/.krb5cc_hpc"
  G-->>Sh: export KRB5CCNAME=FILE:/home/user/.krb5cc_hpc
```


<a id="refresh"></a>

## 7. Background refresh thread

*credd.py :554–627*

```mermaid
flowchart TD
  classDef dmn fill:#d9ecd9,stroke:#4c8a4c,color:#111
  classDef krb fill:#f3e3c3,stroke:#b4873a,color:#111
  classDef dec fill:#ececec,stroke:#888,color:#111
  classDef ext fill:#f2d0cf,stroke:#b5524f,color:#111

  loop["refresh_loop :617<br/>ThreadPoolExecutor(refresh_workers)"]:::dmn --> pass["refresh_pass :579"]:::dmn
  pass --> idle["users idle past active_window"]:::dmn
  idle --> ret["delete master :356, Krb5.forget _krb:353,<br/>_clear_failure :538, drop locks and state"]:::dmn
  pass --> ws{"watch_slurm?"}:::dec
  ws -- yes --> su["_slurm_uids :566"]:::dmn --> sq["squeue -h -a -t PD,CF,R,CG -o %U"]:::ext
  ws -- no --> filt
  su --> filt["keep uid at or above min_uid<br/>and _enrolled :547 → UidMap.principal"]:::dmn
  filt --> dis{"disabled :448?"}:::dec
  dis -- yes --> skip1["log and skip pass"]:::dmn
  dis -- no --> eb["_ensure_broker :363<br/>once per pass"]:::dmn
  eb -. fails .-> skip2["log once, skip pass"]:::dmn
  eb --> map["pool.map(_refresh_one, uids)"]:::dmn
  map --> one["_refresh_one :554"]:::dmn
  one --> bo{"_backing_off :542?"}:::dec
  bo -- yes --> nop["skip this user"]:::dmn
  bo -- no --> ens["ensure(uid) :452<br/>diagram 4"]:::dmn
  ens -. "error, not from_cooldown" .-> rf["_record_failure :529<br/>exponential backoff"]:::dmn
  ens -. "from_cooldown" .-> nop2["ignore: no new attempt was made"]:::dmn
  map --> wait["stop.wait(refresh_interval)"]:::dmn --> pass
```

- A user is refreshed while they have used `krb-get` recently, or (with `watch_slurm`) while they have a pending or running job.
- Each user's mint and install is serialized by the per-uid lock taken in `ensure`, so a request and a refresh never mint the same user twice at once.

<a id="check"></a>

## 8. krb-credd --check [--user NAME]

*credd.py check :696*

```mermaid
flowchart TD
  classDef dmn fill:#d9ecd9,stroke:#4c8a4c,color:#111
  classDef krb fill:#f3e3c3,stroke:#b4873a,color:#111
  classDef dec fill:#ececec,stroke:#888,color:#111
  classDef ext fill:#f2d0cf,stroke:#b5524f,color:#111

  c["check :696<br/>each step prints PASS or FAIL"]:::dmn --> s1["1 config: Config.load :143"]:::dmn
  s1 --> s2["2 trusted files: TicketManager :293 + UidMap :259"]:::dmn
  s2 --> s3["3 MIT version: Krb5.version _krb:319"]:::krb
  s3 --> s4["4 kill switch: disabled :448"]:::dmn
  s4 --> s5["5 uid map: UidMap.principal :265, min_uid"]:::dmn
  s5 --> s6["6 broker TGT: _ensure_broker :363 + klist_times _krb:359"]:::dmn
  s6 --> ws{"watch_slurm?"}:::dec
  ws -- yes --> s7["7 squeue -h -o %U"]:::ext
  ws -- no --> u
  s7 --> u{"--user given and broker OK?"}:::dec
  u -- "kill switch on" --> sk["FAIL: skipped, nothing sent to AD"]:::dmn
  u -- yes --> s8["8 delegation: getpwnam, principal,<br/>_mint :402 into state_dir/.check.uid.cc"]:::dmn
  s8 --> s8b["cache_expiry _krb:363, then delete the file<br/>and Krb5.forget"]:::krb
  u -- no --> end1["exit 0 if all passed, else 1"]:::dmn
  s8b --> end1
  sk --> end1
```

- `--check --user` runs the full mint and validation from diagram 5 but never installs anything into a home directory.

## Function index

| Function | File | Line | Calls |
|---|---|---|---|
| `main` | get.py | 67 | _status, _ask |
| `_status` | get.py | 45 | _ask, _when |
| `_ask` | get.py | 22 | socket connect / send / readline |
| `_when` | get.py | 31 | time formatting |
| `main` | credd.py | 797 | _harden_process, check, Config.load, UidMap, TicketManager, Krb5.version, UidMap.principal, _ensure_broker, Server, refresh_loop thread |
| `_harden_process` | credd.py | 778 | setrlimit, prctl |
| `_assert_secure` | credd.py | 92 | os.stat |
| `Config.load` | credd.py | 143 | _assert_secure, duration_seconds, _name_type, _login_defs_uid_min |
| `_login_defs_uid_min` | credd.py | 224 | reads /etc/login.defs |
| `_name_type` | credd.py | 238 |  |
| `UidMap.__init__ / principal` | credd.py | 259 / 265 | reads uidmap.conf |
| `TicketManager.__init__` | credd.py | 293 | Krb5, _assert_secure, _seed_active |
| `_seed_active` | credd.py | 340 | lists state_dir |
| `master / home_ccache` | credd.py | 356 / 359 | path helpers |
| `_ensure_broker` | credd.py | 363 | klist_times, kinit_renew, kinit_keytab, os.replace |
| `_validate` | credd.py | 385 | Krb5.inspect, validate_user_cache |
| `_mint` | credd.py | 402 | _ensure_broker, s4u_mint, _validate, os.replace |
| `_install` | credd.py | 426 | home_ccache, setpriv → install_ccache.main |
| `due_for_install` | credd.py | 442 |  |
| `disabled` | credd.py | 448 | disable_file.exists() |
| `ensure` | credd.py | 452 | disabled, UidMap.principal, master, cache_expiry, _validate, _mint, home_ccache, _missing, _install, _clear_failure |
| `status` | credd.py | 505 | disabled, UidMap.principal, master, cache_expiry |
| `touch` | credd.py | 524 |  |
| `_record_failure / _clear_failure / _backing_off` | credd.py | 529 / 538 / 542 | backoff bookkeeping |
| `_enrolled` | credd.py | 547 | UidMap.principal |
| `_refresh_one` | credd.py | 554 | _backing_off, ensure, _record_failure |
| `_slurm_uids` | credd.py | 566 | squeue |
| `refresh_pass` | credd.py | 579 | master, Krb5.forget, _clear_failure, _slurm_uids, _enrolled, disabled, _ensure_broker, _refresh_one |
| `refresh_loop` | credd.py | 617 | refresh_pass |
| `_missing` | credd.py | 629 | os.stat |
| `Handler.handle` | credd.py | 643 | status, due_for_install, ensure, touch |
| `check` | credd.py | 696 | Config.load, TicketManager, UidMap, version, disabled, principal, _ensure_broker, klist_times, squeue, _mint, cache_expiry, forget |
| `duration_seconds` | _krb.py | 28 |  |
| `_parse_klist_time` | _krb.py | 42 |  |
| `parse_klist` | _krb.py | 54 | _parse_klist_time |
| `earliest_expiry` | _krb.py | 71 | _parse_klist_time |
| `parse_klist_details` | _krb.py | 113 | _parse_klist_time |
| `_qualify` | _krb.py | 152 |  |
| `validate_user_cache` | _krb.py | 156 | _qualify |
| `parse_mit_version` | _krb.py | 220 |  |
| `classify_error / KrbToolError` | _krb.py | 250 / 262 | maps kvno/kinit stderr to a category |
| `Krb5.run` | _krb.py | 311 | subprocess.run (kinit, klist, kvno) |
| `Krb5.version` | _krb.py | 319 | run (klist -V), parse_mit_version |
| `Krb5._klist_cached` | _krb.py | 332 | os.stat, run (klist) |
| `Krb5.forget` | _krb.py | 353 |  |
| `Krb5.klist_times` | _krb.py | 359 | _klist_cached + parse_klist |
| `Krb5.cache_expiry` | _krb.py | 363 | _klist_cached + earliest_expiry |
| `Krb5.inspect` | _krb.py | 367 | run (klist -e -f), parse_klist_details |
| `Krb5.kinit_keytab` | _krb.py | 376 | run (kinit -k -t) |
| `Krb5.kinit_renew` | _krb.py | 384 | copyfile, run (kinit -R), os.replace |
| `Krb5.s4u_mint` | _krb.py | 406 | copy broker cache, run (kvno -U\|-I -P) |
| `main` | install_ccache.py | 22 | mkstemp, write, fsync, chmod, os.replace |

Line numbers point at each function's `def` in `src/krbhpc/`.

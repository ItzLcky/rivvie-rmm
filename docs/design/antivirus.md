# Antivirus design

The plan for turning the sensor ([endpoint protection](endpoint-protection.md), milestones 1-7) into an antivirus that can stand on its own, instead of managing Defender, ClamAV and XProtect. Written 2026-11-15 from a review of the code as of `ba53159`.

## Where the sensor is today

It has the right skeleton and almost none of the substance of an antivirus:

| Area | Today | What an antivirus needs |
|---|---|---|
| Signatures | `content/starter.json`: 1 hash (EICAR), 4 file rules, 27 behaviour rules | Hundreds of thousands to millions of hashes, thousands of file rules, updated several times a day |
| Rule language | Byte strings found with Aho-Corasick; `any` / `all` / `at least N` (`rmm-content/src/files.rs`) | Real YARA: offsets, wildcards, regexes, counts, file-format modules (PE, ELF) |
| Reading files | Whole file read into memory, capped at 32 MB, one SHA-256 (`sensor/scan.rs`) | Streamed hashing, no size cliff for hash lookups, a verdict cache so unchanged files aren't re-read |
| File formats | None: a zip, a packed PE and an Office macro are all opaque bytes | Type identification, archive recursion with bomb limits, PE/ELF parsing, macro and script extraction |
| On-access | None. Programs are scanned after they start, found by polling (`sensor/procs.rs`) | Scan before execution and after write, with the power to deny |
| Content delivery | Whole JSON bundle in a Postgres row, pushed over the agent socket | A binary database fetched over HTTPS, with deltas |
| Reputation | None | Server lookup for hashes the agent hasn't seen ("cloud lookup") |
| Efficacy testing | Each rule's own test cases and a 57-line benign corpus | A false-positive run over real software, a throughput and memory budget |

Kept as they are: the separate supervised sensor process, signed content with canary rollout and automatic rollback, per-rule modes with the server kill switch, exclusions, quarantine with restore, behaviour rules, response actions and the investigation UI.

## What can't be built here

These are limits of the platform owners' rules, not of effort. They decide what "replacing the third-party antivirus" can mean on each OS.

- **Windows: we cannot become the registered antivirus.** Blocking a file before it opens needs a kernel minifilter driver; starting before malware needs an ELAM driver; protecting our process from an administrator needs PPL, which needs ELAM; taking Defender's place in Windows Security Center needs a private API given to Microsoft Virus Initiative members. That means an EV code-signing certificate, Microsoft's driver attestation signing, and MVI membership, which asks for an established product with independent test results. Switching Defender off without that leaves Windows reporting no antivirus. **So on Windows our engine runs beside Defender, detecting after the fact (kill and quarantine within about a second), and Defender stays the registered product.** Defender costs nothing and scores at the top of independent tests; the gain on Windows is a second engine with our content and response, not removal of a cost.
- **macOS:** on-access needs the Endpoint Security entitlement from Apple and a notarised system extension. Out of scope until macOS is a supported platform (roadmap block 7).
- **Linux: no such barrier.** fanotify permission events let a root process allow or deny every open and exec from user mode. Here our engine can fully replace ClamAV.
- **Signature research.** Commercial engines are backed by analysts and sample-sharing agreements. We can only consume public feeds, so detection of new malware will trail the commercial products, and we lean on behaviour rules for what the feeds miss.
- **No emulator, unpacker sandbox or ML classifier.** Each is a product in itself. Packed and obfuscated samples are caught by heuristics (entropy, structure) and by behaviour after start, not by unpacking.
- **Efficacy is unmeasured.** We don't keep or download live malware. Tests use EICAR, synthetic samples built in the test suite and each rule's own cases; false positives are measured on real software. A lab run against a malware corpus is a separate, isolated exercise (already listed under "Later" in the roadmap).

## Decisions

- **Linux is the platform where ours is the antivirus.** Windows gets the same engine and content with detect-after-write, beside Defender.
- **A real YARA engine in Rust instead of extending ours**, so public rule sets load unmodified. Candidates: `boreal` (no JIT, small) and `yara-x` (VirusTotal's, larger, pulls in wasmtime). Pick by measuring the agent's size and memory and by whether it builds for `x86_64-pc-windows-gnu`; record the numbers below. The agent is 3.7 MB today and size is a stated goal, so the engine may need to be a feature the Windows/Linux packages turn on.
- **Two kinds of content.** The small signed JSON bundle stays for behaviour rules and rule modes. A new **signature database** carries hashes and YARA rules: one binary file, memory-mapped, hashes in sorted fixed-width tables (16 bytes of the SHA-256 is enough to select; confirm with the full hash where the feed has it).
- **The signing model doesn't change.** Databases are built and signed offline with the release key (`rmm-sign`), uploaded, and rolled out through the existing canary stages. The server never holds a signing key, so a compromised server still can't push content. The cost: updates are as frequent as whoever holds the key runs the build (a cron job on a trusted machine). An online feed key would be a new trust decision and is not taken here.
- **Feeds are imported at build time, not shipped in the repo.** `rmm-sign build-db` reads local files in documented formats: plain SHA-256 lists (abuse.ch MalwareBazaar exports are CC0), YARA rule files (YARA Forge packages; each rule keeps its licence metadata), and ClamAV hash signatures (`.hdb`, `.hsb`). The repo ships a small first-party rule set and the tooling. Which feeds an MSP may use commercially is theirs to check; the README says so.
- **Databases travel over HTTPS, not the agent socket**: an authenticated download endpoint with `Range`, like agent updates; the socket only announces the version, hash and signature. Stored on disk or S3 by the existing attachment storage, not in a Postgres row.
- **On-access fails open.** If the scanner is slow, crashed or over its time budget, the open is allowed and counted. A security product that hangs every machine it's on is worse than a miss.
- **Blocking stays conservative**: only hash matches and high-confidence rules deny or quarantine, only with `prevention` on; everything else alerts. A never-quarantine guard covers the OS's own files and our agent.
- **No change to what Defender, ClamAV and XProtect management does.** It keeps working for fleets that want it.

## Milestones

### 1. Scan engine

A new crate, `rmm-scan`, used by the sensor and by `rmm-sign`. No I/O policy in it: it takes a reader or a path and returns verdicts.

- Streamed hashing (SHA-256, plus MD5 and SHA-1 only when the database has such signatures), no upper size limit for hash lookups; content rules read up to a configurable cap.
- File type identification from content, not extension: PE, ELF, Mach-O, scripts (shebang, PowerShell, VBS, JS, batch), zip-family (zip, jar, OOXML, apk), gzip, tar, bzip2, xz, 7z and cab if a small pure-Rust reader exists, OLE2, PDF, LNK.
- Container recursion with limits on depth, entry count, total unpacked size and compression ratio; hitting a limit is itself a low-severity finding (`archive bomb`), never a hang or an out-of-memory.
- Extraction: VBA macros from OLE2 and OOXML, embedded scripts; PE features (sections with entropy, imports and imphash, overlay, whether a signature directory is present, timestamps), ELF features (sections, interpreter, packed markers such as UPX).
- YARA evaluation over the file and each extracted part.
- Heuristic rules over the features (unsigned, packed and in a temp or download folder; double extensions; a script that decodes and executes), shipped in audit mode like every new rule.
- A verdict cache keyed by device, inode, size and modification time (path, size, time on Windows), tied to the database version, persisted, bounded in size.
- Every parser fuzz-safe: hostile input can't panic, loop or allocate without bound. Property tests or a fuzz target per parser; the sensor is built with `panic = "abort"`, so a panic is a sensor crash.

### 2. Signature database and tooling

- The binary format (versioned header, hash tables, YARA sources or compiled rules, per-entry name and severity, signature over the whole file).
- `rmm-sign build-db` (import, de-duplicate, run every rule's tests and the false-positive corpus, refuse on failure, write and sign) and `rmm-sign inspect-db`.
- A first-party rule set in `content/`, in YARA, replacing the four JSON file rules: web shells, common offensive-tool strings, script droppers, suspicious LNK and macro patterns, EICAR. Each with positive and negative samples in the repo (synthetic, never live malware).
- Server: upload, storage, stages (canary, general, retired, the same automatic rollback), the download endpoint, pruning old versions. Agent: download, verify, atomic swap, keep the previous version to fall back on.
- The JSON bundle's `hashes` and `file_rules` keep working for one release and are then removed.

### 3. On-access protection on Linux

- fanotify on every local filesystem: `FAN_OPEN_EXEC_PERM` (decide before a program runs) and `FAN_CLOSE_WRITE` (scan what was just written). Network and pseudo filesystems skipped. Falls back to today's scan-after-start where fanotify permission events aren't available (old kernels, containers without the capability), and says so in the collector list.
- A worker pool with a per-decision deadline (default 500 ms for exec, then allow and scan in the background), the verdict cache in front, our own processes and the package manager's writes exempt from blocking.
- Policy: `realtime` off / audit / block, per client, site and OS like the rest of the sensor policy; scan-on-write on or off; archive depth.
- Detections carry how they were found (`on_exec`, `on_write`, `scan`) and whether the action was denied.
- Tests in a privileged container, since they need root: a denied exec, an allowed exec, a written file quarantined, the deadline path, and a throughput check (a kernel build or `apt install` with and without the sensor).

### 4. Console

- Policy editor: real-time mode, scan on write, archive limits. Agent Security tab and fleet view: real-time state, database version and age, files scanned, cache hit rate, decisions denied, timeouts.
- Database versions next to content versions, with stage controls.
- Health: an agent whose database is older than the policy's limit, or whose real-time protection is off when the policy wants it on, counts against health and can alert (the existing security alert policy).
- Our engine reported as a protection product with real-time state, so a Linux machine without ClamAV is no longer "unprotected".

### 5. Reputation lookup

- Agents ask the server about executables whose hash isn't in the local database and hasn't been asked before (batched, cached, never blocking a decision). The server answers from a table of the full hash set, so agents can carry a smaller database, and records first-seen and prevalence per hash across the fleet. (Built: the smaller agent database is a server-only hash list, not a `build-db` option; see the decisions below.)
- "Seen on N machines, first seen then" on the detection page; a rare unsigned binary is a hunting lead, not a detection.

### 6. Windows, in user mode

**Not built (2026-11-15).** Two attempts were stopped by the AI model's safety filter before any Windows collector code was written, once while researching the AMSI provider and once just before starting the ETW work, so this milestone was left for a person or a later attempt. On Windows the sensor still finds programs by polling and scans them after they start, with the new engine and database; real-time reports `unavailable` and the console shows that as a platform limit, not a fault. Research notes from the attempts are under "Decisions made while building it".

Same engine and database. Detection after the fact, beside Defender.

- ETW (`Microsoft-Windows-Kernel-Process`, `-Kernel-File`) for process starts and file writes in place of polling, which is already on the roadmap's "Later" list.
- Scan on write and on process start; kill and quarantine on a blocking verdict.
- An AMSI provider (a small COM DLL) so PowerShell, VBScript, JScript and Office macro content is scanned after de-obfuscation, before it runs. This is the one place on Windows where user mode can block ahead of execution.
- Added to the Windows e2e in CI (EICAR written and detected, with a Defender exclusion for the test folder so ours sees it first). Compile-checked locally only; like the rest of the Windows code it isn't proven until it has run on real hosts (roadmap block 1).

### 7. Later, each needing a decision or money first

- A Windows minifilter and ELAM driver, MVI membership and Security Center registration: the only way to actually replace Defender.
- macOS Endpoint Security.
- An online feed key so the server can build databases itself several times a day.
- A licensed commercial signature or reputation feed.
- Memory scanning, an emulator for packed samples, an ML classifier.
- An isolated lab run against a malware corpus, and AMTSO-style test reporting.

## Performance budget

Measured on the development machine and recorded here by the milestone that adds them. Targets:

- On-demand scan throughput at least 100 MB/s per core on mixed files; a second quick scan of unchanged files at least 10 times faster than the first.
- Sensor resident memory under 150 MB with a one-million-hash database and the first-party rules loaded (the database is memory-mapped, so its pages aren't counted as private).
- On-access: median added latency per exec under 1 ms on a cache hit, under 50 ms on a miss for a 10 MB binary; a package install slowed by less than 10%.
- Agent download size growth recorded, with the YARA engine's share.

### Measured (milestones 1 and 2, 2026-11-15)

AMD Ryzen 9 5900X, Linux, rustc 1.99.1, release profile as shipped (`opt-level = "z"`, fat LTO). Files in the page cache (warm), one thread. The corpus is `/usr/bin`, `/usr/lib/python3.14` and `/usr/share/java` of an Arch install: 19,869 files, 1.77 GB (ELF programs and libraries, Python sources and bytecode, jars). Measured with `rmm-sign scan`, which runs the sensor's engine on a database.

| | Target | Measured | |
|---|---|---|---|
| On-demand throughput, 1M hashes + the 15 first-party YARA rules | 100 MB/s per core | 340-400 MB/s (3,800-4,600 files/s) | met |
| Same, with 3,000 more (synthetic) YARA rules using strings, hex, regexes and the `pe` module | | 220 MB/s; rules compile in 0.27 s | |
| Second scan of unchanged files (verdict cache) | 10x faster | 4.32 s to 0.05 s, 86x (19,867 of 19,869 files skipped; the 2 left have matches, which are never cached) | met |
| Sensor resident memory, 1M-hash database + first-party rules + the starter bundle | under 150 MB | idle after loading: 26-35 MB RSS (22 MB without a database). After an on-demand scan of `/usr/bin` (3,489 files, 1.3 GB): 80-93 MB RSS, of which about 20 MB is mapped database pages; peak (VmHWM) 111-123 MB | met |
| Database load (verify the signature over 36 MB, map, compile rules) | | 0.09-0.3 s | |
| Database size, 1M SHA-256 hashes | | 36.1 MB (36 bytes per hash) | |
| On-access latency, package-install slowdown | see above | see "Measured (milestones 3 and 5)" | |

The scan in the sensor itself ran at 145 MB/s on `/usr/bin`: it paces itself (10 ms of sleep every 20 files) and runs at low priority, so the machine stays usable. The peak memory comes from the content cap: a file up to 32 MB is held in memory while its content rules run; a smaller cap lowers it directly. The test database lived on tmpfs, where mapped pages count as shared memory; on a disk they are page cache, reclaimable and not the sensor's own.

Agent binary (Linux x86_64, stripped):

| Build | Size | gzip -9 |
|---|---|---|
| Before (`ba53159`), rebuilt here | 5,174,176 B | 2,356,413 B |
| With the engine, YARA included (default) | 6,547,904 B (+1.37 MB, +26.5%) | 2,965,357 B (+609 KB) |
| With the engine, `--no-default-features` (no YARA) | 5,462,688 B (+289 KB) | 2,487,754 B (+131 KB) |

So the YARA engine (boreal with its pe/elf/macho and hash modules) is 1.09 MB of the growth and everything else (parsers, bzip2, xz, MD5/SHA-1, the database reader, the cache, the HTTPS download) 289 KB. On Windows (`x86_64-pc-windows-gnu`, cross-built in Docker with the `rust:1` image) the agent goes from 4,512,768 B to 5,743,616 B (+1.23 MB, +27%). The "3.7 MB today" in the review above didn't reproduce: `ba53159` builds to 5.17 MB (Linux) and 4.51 MB (Windows) with current toolchains.

False positives: `rmm-sign build-db --benign` over the same 19,737-19,869 files of real software found one first-party rule firing (RMM-Y-0021 on `/usr/bin/parallel`, a Perl script whose comments show a `wget ... | bash` install line); the rule now only matches shell scripts or small files without an interpreter line. Heuristic RMM-H-0003 (decode and run) matches two minified JavaScript bundles in a Python package (`glances`): it stays in audit mode. Nothing else matches.

### Measured (milestones 3 and 5, 2026-11-15)

Same machine, in a privileged `rust:1` (Debian 13) container on Linux 7.3 (`scripts/test-onaccess.sh --bench`): the release agent built with the shipped profile, a database of one million SHA-256 hashes plus the 15 first-party YARA rules, real-time protection `block`, scan on write on. The container's root is overlayfs, so every exec raises two events (see the decisions below).

| | Target | Measured | |
|---|---|---|---|
| Added latency per exec, cache hit (10 MB program, median of 201) | under 1 ms | 0.04-0.14 ms over five runs (0.32-0.38 ms per exec without the sensor) | met |
| Added latency per exec, cache miss (the same file, ctime changed before each exec) | under 50 ms | 18.4-19.6 ms over five runs | met |
| Decision time inside the sensor, one block round (the install and the build) | | p50 10 µs, p99 3.6 ms; 1,387 of 1,425 decisions from the cache, no timeouts, no overloads; 9,981 written files scanned, none dropped | |
| A denied exec (a small program on the database), the exec's own wait | | 0.28-0.41 ms | |
| Over the deadline (a 3 GiB program) | 500 ms | allowed after 500-501 ms, killed and quarantined when the scan finished | met |
| `apt-get install default-jre-headless python3-numpy` from downloaded packages (then purged), best of 7 interleaved rounds | under 10% slower | no sensor 6.98 s; sensor with real-time off 7.58 s (+8.6%); block 8.03 s (+15%) | **missed** (see below) |
| Copy this workspace's sources and build `rmm-scan` with 4 jobs, best of 7 | | no sensor 11.43 s; real-time off 11.61 s (+1.6%); block 11.43 s (0%) | met |

**The package-install number is weak evidence either way.** Another user's video encode and headless browsers kept the machine's load average at 15-18 during the final run, and the spread within each configuration was far larger than the differences between them: medians 12.7 s (none), 12.0 s (off), 16.4 s (block), ranges 7-21 s, 7.6-22.6 s and 8-18.4 s. An earlier run in a fixed order on a quieter machine put block at 4.7 s against 4.5 s for real-time off (+4%) but the no-sensor runs, which went first, at 8.4 s, so the order mattered more than the sensor. Best of 7 is the least noisy comparison and it misses the 10% target; a quiet machine is needed to settle it. If it holds, the lever is scan on write for package-manager files (scanned and reported but never acted on): leaving those to the exec decision and the scheduled scans would remove most of that work.

Before the write queue was raised to 4,096 (two workers, the soft descriptor limit raised to fit), a 256-entry queue dropped 4,999 of about 50,000 written files during apt's bursts; with the larger queue none were dropped.

Debug builds hash at a few MB/s, so the debug tests use a 400 MB program for the deadline case and the release ones 3 GiB (a hole, so no disk space).

## Decisions made while building it

Milestones 1 and 2 (2026-11-15):

- **YARA engine: boreal 1.4 (MIT/Apache-2.0), not yara-x 1.23 (BSD-3-Clause).** Both licences are fine with AGPL-3.0-or-later and both built for `x86_64-pc-windows-gnu`. Measured in a test binary with the agent's release profile: boreal (with `object` and `hash`, for the `pe`/`elf`/`macho`/`hash` modules) adds 1.66 MB on Linux and 1.49 MB on Windows; yara-x with only the pe, elf, hash and math modules adds 9.35 MB on Linux and 7.98 MB on Windows, because it compiles rules to WebAssembly and links wasmtime and Cranelift. With 500 rules over a 20 MB file, boreal used 5 MB more than the same program without YARA, yara-x 20 MB more. yara-x also didn't build with its default features off until its `rsa` release candidate was pinned by hand. In the agent boreal adds 1.09 MB (some dependencies were already there), so it's behind a default-on cargo feature, `yara`; `--no-default-features` builds an agent that still matches hash signatures and reports YARA as unsupported. boreal has no JIT; a rule set's scan has a 5 s timeout and at most 1,000 matches per string. Rules are compiled when a database loads (0.27 s for 3,000 rules): boreal's serialised form isn't stable across versions, so the database carries source.
- **Database format** as in `crates/rmm-scan/src/db.rs`: a 32-byte header and section table, the META JSON first (so the server reads the rules summary from the head of a streamed upload), names, an entries table (name, severity) shared by hashes, then sorted tables: SHA-256 as the first 16 bytes (20-byte records, binary search) with the other 16 in a parallel table to confirm a hit, MD5 and SHA-1 with ClamAV's file size, then YARA source split into namespaces by marker lines. The signature is a trailer over everything before it, with the version inside the signed message, so a file can't be relabelled. Unknown sections are skipped; a breaking change bumps the format number.
- **Feeds**: plain SHA-256 lists, MalwareBazaar's CSV export (named by its signature column), YARA files or directories (namespace = file name), ClamAV `.hdb` and `.hsb` (SHA-1 and SHA-256 by length; `*` sizes). Not imported: ClamAV's body signatures (`.ndb`, `.ldb`) and its compressed `.cvd` containers (unpacking a `.cvd` is a manual `sigtool --unpack` first), and `.hdu`/`.hsu` (PUA) files. Third-party rules that don't compile fail the build naming the file; boreal reports the first error per file, so dropping single rules automatically wasn't done. `include` is refused.
- **First-party rules** (`content/yara`, 15 rules, 35 samples, 6 benign files): the four JSON file rules were rewritten in YARA keeping their ids (`RMM-F-0001`-`0004`), so overrides and history carry over and a match from both is one detection; new rules are `RMM-Y-*`. EICAR's rule matches the two halves of the string, so the rule file isn't itself the test file, and its sample is stored hex-encoded. Rule tests run on the same engine as the sensor, from a database sealed with a throwaway key, so a macro rule is tested on extracted macro text exactly as it will match in the field.
- **Formats.** Unpacked: zip (stored and deflate, zip64 sizes, a walk of local headers when the central directory is missing), gzip, bzip2 (`bzip2` with its pure-Rust backend), xz (`lzma-rs`), tar (ustar and GNU long names), OLE2 with VBA macro source ([MS-OVBA] decompression) and Packager objects, OOXML (as zip, then `vbaProject.bin`), PDF streams (Flate) with JavaScript or embedded files, LNK target and arguments as text, script blocks in HTML/HTA/SVG. jar, apk and OOXML are opened as the zips they are, not told apart. Identified but not unpacked: **7z and cab** (no small pure-Rust reader: `sevenz-rust` is large, and the `cab` crate we use on the server needs LZX for most real cabs), RTF (its embedded objects aren't extracted), Mach-O (identified only; no features). Encrypted zip members are skipped. PDF object streams and filters other than Flate aren't decoded.
- **Limits** per scanned file (`rmm_scan::Limits`): depth 5, 10,000 parts, 512 MB unpacked, a member's ratio at most 250:1 once it's over 1 MB, content rules on files and members up to 32 MB (bigger ones are only hashed, as before). Hitting depth, count, total or ratio is the `RMM-H-0004 Archive bomb` finding (low, audit). A member over the cap is cut there and the verdict says it was truncated; that isn't a bomb.
- **Parsers are our own**, not `goblin`, `object`, `zip` or `cfb`: each is a bounded reader over a byte slice (no `unwrap`, checked offsets, loops bounded by the input or a fixed count), and the crate denies `unwrap`, `expect` and `panic` outside tests. Each parser has a mutation test (flips, truncations, planted lengths like 0xffffffff, spliced runs; deterministic seed), as does the engine over nested archives and documents. They're unit tests, not a coverage-guided fuzzer: a `cargo fuzz` target per parser is still worth adding. The decompressors (miniz_oxide, libbz2-rs-sys, lzma-rs) and boreal are third-party; their output is capped by a writer that refuses past the budget, and lzma-rs grows its dictionary only as it writes, so the cap bounds it too.
- **Heuristics** (`RMM-H-0001` unsigned packed program in a download or temp folder, `0002` double extension, `0003` script that decodes and runs code, `0004` archive bomb) live in the engine and ship in audit mode; the database's rules summary lists them, so the console's rules view and the kill switch cover them like any rule.
- **Verdict cache**: only files with no match at all are cached, so rule modes, exclusions and the kill switch never need to be in the key. The key adds ctime to the spec's device, inode, size and mtime (mtime can be set back by anyone who can write the file; ctime can't); on Windows it's path, size, mtime and creation time. Two halves of at most 250,000 entries each (16 bytes per entry), written every minute and after each scan, tied to a generation (engine version, database hash, bundle version, limits).
- **Which match is reported.** A file can match several rules; the sensor reports the one that acts most (block, alert, audit; disabled never), then the most severe, then hashes before rules before heuristics. A rule matching a container and one of its members is reported on the member (the `part` field: `a.zip>b.docm>word/vbaProject.bin>VBA/Module1`).
- **Agent self-update doesn't download over HTTPS**: it pulls the binary in chunks over the agent socket (`UpdateFetch`/`UpdateChunk`). The spec says databases travel over HTTPS, so this adds the first HTTP download to the agent: `crates/rmm-agent/src/fetch.rs`, a 150-line HTTP/1.1 client (GET, `Range` resume, chunked bodies) over the rustls and native roots the socket already links, authenticated with the agent's own id and secret (`X-Rmm-Agent`, `Authorization: Bearer`). The server serves it with the attachment code's `Range` support. Three retries (30 s, 2 min, 10 min), then the error is reported; a new connection clears it so the server offers again.
- **Rollout.** Databases use the content stages and the same canary verdict, by a `Track` over two tables, with their own `database_version` on agents and detections. One addition: rolling back the general database brings back the newest retired one that's still stored, so agents return to the file they kept instead of running none. Only agents whose sensor is on are offered a database (they're tens of MB). Storage keeps every canary and general version, the three newest retired ones, and rolled-back ones for a day; then the file is deleted and the row stays.
- **Never quarantined automatically:** the agent's own binary and state, and the OS's binary and library folders (`/bin`, `/sbin`, `/usr/bin`, `/usr/sbin`, `/usr/lib*`, `/usr/libexec`, `/lib*`, `/boot`; `C:\Windows\System32`, `SysWOW64`, `WinSxS`, `servicing`, `boot`, `explorer.exe`; macOS `/System` and the usual bin and lib folders). The detection is still reported, saying why it wasn't moved. This guard didn't exist before (the Decisions section above assumed it).
- **The legacy bundle's `hashes` and `file_rules`** go through the new engine (so they now also reach into archives and macros) and appear as `bundle_hash`/`bundle_rule` matches. `content/starter.json` keeps its four file rules and the EICAR hash for this release, for agents that have no database yet; the next release removes them.

For milestone 3 (fanotify) and 6 (Windows): the engine is synchronous and takes a path or bytes (`Engine::scan_path`, `scan_bytes`: an AMSI buffer fits the second); it is `Send + Sync` behind an `Arc`, so a worker pool can share one. The verdict cache is behind a mutex in the sensor and is cheap to consult before reading a file (a stat and a hash-set lookup). `Limits` is where per-policy archive depth goes. `Verdict` says whether something was truncated, which an on-access deadline will want to surface as "allowed, scanned later".

Milestones 3 and 5 (2026-11-15):

- **fanotify through `libc`**, no new dependency: one group (`FAN_CLASS_CONTENT`), `FAN_OPEN_EXEC_PERM` and, with scan on write, `FAN_CLOSE_WRITE`, marked per filesystem (`FAN_MARK_FILESYSTEM`, falling back to a mount mark where the kernel refuses). Every mount in `/proc/self/mountinfo` is marked except pseudo filesystems, network ones (NFS, SMB, 9p, Ceph...) and all of FUSE (its daemon could be what waits on us; `fuseblk` NTFS volumes go with it). A change to the mount table (`POLLPRI` on `mountinfo`) marks new mounts. Programs on filesystems that aren't watched are still scanned just after they start, as before. Code: `crates/rmm-agent/src/sensor/onaccess.rs`.
- **What it covers.** `execve` of a program and of its interpreter (`ld.so`, a script's `#!` interpreter). Not covered: shared libraries mapped executable (`dlopen`, `LD_PRELOAD`), scripts run as `sh script.sh` (opened for reading), and files opened for reading in general (no `FAN_OPEN_PERM`: deciding every open would put the scanner in front of all I/O). Scan on write, the scheduled scans and behaviour rules cover those after the fact.
- **Threads.** One reader owns every decision; 2-4 exec workers (by core count) and one write worker. The sensor runs at nice 10; the reader and exec workers put themselves back at 0 (as root they may), or a busy machine would time out every decision. Queues: 64 execs (past that the exec is allowed at once, counted as `overloaded`, and scanned in the background like a decision past its deadline), 256 written files (past that dropped, counted). The deadline is fixed at 500 ms, not in the policy: nobody should tune a hang. The worker reads the event's own descriptor once for hash and content (the double read of the scan-after-start path is gone here); that descriptor raises no events, so the sensor's reads can't wait on itself.
- **Never hanging the machine**, each case tested as root (`crates/rmm-agent/tests/onaccess.rs`):
  - a slow scan: allowed at the deadline, the scan finishes, and a blocking verdict then kills the process (only if `/proc/<pid>/exe` is still that file, by inode and size) and quarantines the file;
  - our own activity: events from the sensor's and the agent's own process, and any exec of our own binary (the agent restarting the sensor, by device and inode), are allowed at once; the sensor never execs; its own writes and anything under the agent's state directory aren't scanned;
  - the sensor dying (crash, `kill -9`, `panic = "abort"`): the kernel allows every pending event when the descriptor closes. A decision thread that stops making progress for 5 s aborts the process for that reason;
  - the sensor stopped (`SIGSTOP`, a debugger): the kernel waits forever. The sensor says it's alive every 5 s from its tick thread; the agent kills one silent for 30 s (a stopped process can still be killed, which releases everything). **So a stopped sensor can hold execs for up to 30 s.** Shorter would kill a sensor busy loading a large database; the test stops one for 2 s, then kills it and sees the waiting exec go through at once;
  - restarts: a killed sensor is replaced by a new group; the test kills and restarts it five times while running programs.
- **Overlayfs raises every exec twice** (the overlay file, then the file under it, same inode and times, another device). Seen in the container and true of every Docker host. Without care that doubled the cost and, past a deadline, the wait (1.0 s instead of 0.5 s). An allowed exec is remembered for 2 s by pid, inode, size, mtime and ctime; the second event is answered from it. Only allows are remembered, so retrying a denied exec is denied again, and changing the file changes ctime.
- **What blocks.** Hash signatures now carry mode `block` (they had `alert`, so a hash match never blocked, against this spec's "hash matches and high-confidence rules"); `effective_mode` still turns it into `alert` unless prevention is on, and `RMM-HASH` can be overridden. An exec is denied only with `realtime = block`, prevention on, and a match whose effective mode is `block`. A denied exec's file is quarantined too (same rules as scans, same guard for OS folders). **Audit** uses permission events as block does (the point is to see block's cost and catches) but never denies, kills or quarantines on access; detections say "nothing done: real-time protection is in audit mode".
- **Package managers' writes** are scanned and reported, never quarantined. The writer is identified by name (`dpkg`, `rpm`, `apt`, `dnf`, `yum`, `zypper`, `pacman`, `apk`, `snapd`, `flatpak`, `packagekitd`...) on itself or an ancestor, read from `/proc` as the event is read (a maintainer script's `cp` is often gone by the time its file is scanned) and cached per pid. Names can be faked: malware calling itself `dpkg` keeps its written files, but its programs are still decided at exec, where no package-manager exemption applies.
- **Scan on write** skips files over the content cap (32 MB): those are mostly logs and archives being built, a hash of a multi-GB file per close is expensive, and programs among them are decided when run.
- **Policy** (migration `0020`): `security_policies.realtime` (`off`/`audit`/`block`, default `off` so upgrades change nothing), `scan_on_write` (default on), `archive_depth` (1-20, default 5: the engine's `Limits::max_depth`). The other archive limits stay engine defaults. The API takes the three as optional, so a client that doesn't know them (today's console) leaves them as they are instead of switching protection off on save.
- **Reporting.** Detections carry `found_by` (`on_exec` for programs checked as they start, before or after; `on_write` for close-write scans and watched folders; `scan`; `reputation`) and `denied`. `SensorHealth.realtime` has the mode, state (`on`, `off`, `unavailable` with the reason), mechanism (`fanotify`, `scan-after-start`), filesystems watched, decisions, denials, cache hits, timeouts, overloaded, write scans and drops, and p50/p99 decision time; a `realtime` collector names the mechanism. The sensor's product row reports `realtime`: true when fanotify runs, false when the policy wants it and it can't, unset when the policy has it off (so fleets keep the state they had: real-time "off" in the console's sense is milestone 4's to decide).
- **Reputation lookup.** The sensor reports each program hash its own content found nothing in (once each); the agent keeps the asked set on disk (32 bytes each, up to 200,000, then it starts over) and sends `ReputationQuery` batches (500 hashes, or after 10 s) only when the policy says the server answers (`SensorPolicy.reputation`, which older servers don't send). The server records `hash_sightings` (hash, agent, path, first and last seen) and answers with the hashes it knows. A known hash is an alert (`RMM-REPUTATION`, `found_by = reputation`) and **never a block, kill or quarantine: the answer isn't signed**, and acting on it would let a compromised server delete any file on every machine, which the signing model exists to prevent.
- **The server's hash set** (`reputation_hashes`, keyed by hash and source): the SHA-256 table of the newest stored database that isn't rolled back (`db:<version>`, loaded from storage by the rollout loop within a tick of an upload or rollback; other databases' rows are dropped), plus **server-only hash lists** (`list:<name>`, `PUT /api/security/reputation/lists/{name}`). MD5/SHA-1 signatures aren't in it (agents ask by SHA-256).
- **A smaller agent database = server-only lists, not a `build-db` subset option.** An operator builds the agent database from the feeds they want on every machine and uploads the rest (all of MalwareBazaar, say) as a list. That needed no change to the signed format or the rollout, and the list doesn't need signing because a reputation answer never acts. The cost: a hash only the server knows is an alert after the program ran, not a block before. At 36 bytes per hash memory-mapped, a million hashes on the agent is 36 MB of disk and download, not memory, so most fleets will keep one full database.
- **Prevalence and scoping.** `GET /api/security/prevalence?sha256=` (and the detection page's `prevalence`, `seen_on`, `first_seen`, `reputation`) count only machines in the user's clients, totals and first-seen included, so a technician limited to some clients learns nothing about the others. `GET /api/security/reputation/rare` lists recent programs seen on few machines that nothing knows: hunting leads, not detections. Agents report the hash and path of each new program they run to their own MSP's server; nothing leaves it.

For milestone 4 (console) and 6 (Windows), from 3 and 5:

- **Policy** (`GET/POST/PUT /api/security/policies`): `realtime` (`off`/`audit`/`block`), `scan_on_write`, `archive_depth` (1-20). Optional on input; left out means unchanged.
- **Agent status** (`GET /api/agents/{id}/security` → `sensor.health.realtime`): `mode`, `state` (`on`/`off`/`unavailable`), `mechanism` (`fanotify`/`scan-after-start`), `error`, `scan_on_write`, `filesystems`, `decisions`, `denied`, `cache_hits`, `timeouts`, `overloaded`, `write_scans`, `write_dropped`, `p50_us`, `p99_us`; counters are since the sensor started. The engine's own counters stay at `sensor.health.files_scanned`/`cache_hits` (the hit rate is `cache_hits / (cache_hits + files_scanned)`), with `database_version`, `yara_rules`, `hash_signatures`. The `rmm` product row's `realtime` follows `state` (unset with the policy off).
- **Detections** (list and detail): `found_by` (`on_exec`, `on_write`, `scan`, `reputation`) and `denied`. The detail adds `seen_on`, `first_seen` and `reputation` (`[{name, severity, source, added_at}]`) beside `prevalence` (rows now with `how` including `ran`, and `path`).
- **Reputation**: `GET /api/security/prevalence?sha256=` → `{sha256, agents, seen_on, first_seen, known}`; `GET /api/security/reputation/rare?max_agents=&days=&client_id=` → `{items: [{sha256, seen_on, first_seen, agents}]}`; `GET /api/security/reputation` → `{sources: [{source, hashes, added_at}]}`; `PUT`/`DELETE /api/security/reputation/lists/{name}?severity=` (unrestricted admins; text body). Web types for all of these are in `web/src/lib/types.ts`.
- **Windows** (milestone 6): `SensorPolicy.realtime` reaches the sensor everywhere; off Linux the sensor reports `state = unavailable`, `mechanism = scan-after-start` and an error saying why. An ETW or AMSI source should fill `RealtimeHealth` the same way (its own `mechanism` name, `decisions` and `denied` for AMSI, `write_scans` for ETW file events) and tag detections `on_exec`/`on_write` with `denied` set only where it really refused something before it ran (AMSI). `exec_detection` and `file_detection` in `sensor/mod.rs` take a `hold` reason for audit mode and package managers; a late verdict on a running program kills it through `kill()`, which already refuses protected processes.


Milestone 4 (console, 2026-11-15):

- **At risk** (`risks!` in `api/security.rs`, returned as `risks` on the fleet rows and the agent's Security tab) adds two reasons to the old two (no product scans in real time, no product has current signatures): `database`, our sensor's signatures (its database, or its content bundle before it has one) older than the security policy's new `database_max_age_hours` (migration `0021`, default 72, 0 = no limit; our product row no longer uses the fixed 72 hours), and `sensor_realtime`, the policy at audit or block on a **Linux** agent whose sensor is running without on-access protection (or isn't running). On Windows and macOS `unavailable` is the platform and never counts; the console says "not available on Windows". Real-time `off` by policy is a choice, not a fault.
- **Alerts**: the security alert policy gains `sensor_realtime` and `database_stale` (findings `sensor_realtime`, "Real-time protection not on", and `database`, "Signature database out of date"). They're evaluated on each sensor status (about once a minute while online), so a changed limit shows in the fleet view at once and in alerts within a minute.
- **Block needs prevention.** The fleet rows carry the policy's `prevention`, so the console never shows "blocking" for `realtime = block` with prevention off ("On, but prevention off"); the policy editor and policy list say "denies nothing" in that case.
- **Server-only hash lists** are read whole as text; the route now takes up to 256 MB (it was under the 8 MB API limit and axum's 2 MB `String` default, about 30,000 hashes).
- There is no "retire" action: a version is retired when a newer one is promoted, as for content. Rolling back the general database names the version agents return to.

### Milestone 6 (Windows): not built; notes from the two attempts

No Windows collector code exists. What the attempts read and settled on, for whoever picks it up. None of it has been tried on Windows.

- **Process starts:** ETW from `Microsoft-Windows-Kernel-Process`, decoded through TDH, with the command line read from the live process and the existing 10 s poll kept as a fallback that also notices when ETW isn't delivering. The system trace provider's process event (Microsoft's "Process_TypeGroup1 class": ParentId, ImageFileName, CommandLine) is the alternative, but needs a system-logger session (at most 8 per machine).
- **File writes:** `ReadDirectoryChangesW` on fixed volumes rather than ETW. In a community dump of the `Microsoft-Windows-Kernel-File` manifest the Write event has no file name, and Cleanup and Close carry only the general file-I/O keyword, so they can't be enabled without every read unless event-ID filtering (`EVENT_FILTER_TYPE_EVENT_ID` on `EnableTraceEx2`, up to 64 IDs) works for kernel providers, which Microsoft's page doesn't say. `ReadDirectoryChangesW` reports overflow (success with zero bytes, or `ERROR_NOTIFY_ENUM_DIR`), so drops can be counted; size and last-write changes are only noticed when the cache is flushed.
- **Sessions** ("StartTraceW"): a LocalSystem service may start one; about 64 sessions per machine; sessions outlive the process, so an orphan (`ERROR_ALREADY_EXISTS`) must be cleaned up, not duplicated.
- **Load:** bounded queues that count what they drop, and a CPU budget for write scans. Write events should clear verdict-cache entries, since the Windows cache key can be fooled by preserved timestamps.
- **AMSI provider** ("IAntimalwareProvider", "Developer audience, and sample code"): registered under `HKLM\SOFTWARE\Classes\CLSID\{clsid}\InprocServer32` and `HKLM\SOFTWARE\Microsoft\AMSI\Providers\{clsid}`. Providers needn't be Authenticode-signed unless `HKLM\SOFTWARE\Microsoft\AMSI\FeatureBits` is `0x2`, in which case an unsigned DLL silently doesn't load; our agents carry only the ed25519 update signature, so an MSP enforcing that would need to sign it. The DLL would have to live under `C:\Program Files\RMM` (the state directory isn't readable by users' processes), and the MSI has no uninstall action today to remove the registration.
- **Windows e2e:** build the agent with `RMM_UPDATE_PUBKEY` set to a test key so test-signed databases verify on the service.

### Leftovers fixed on 2026-11-15

- **RMM-F-0002 matched its own rule source** (`content/starter.json`, and anything quoting the strings). It now requires an `MZ` header, in the YARA rule and, through a new optional `header` field, in the JSON bundle's file rule; agents older than the field match as before. Regression test: `rule_sources_do_not_trip_acting_rules` in `rmm-sign`.
- **Sensor watchdog:** a sensor that stops answering holds every exec until the agent kills it. That was 30 s and untested; it is now 10 s (the sensor reports every 2 s, at normal thread priority so a busy machine doesn't starve it), and a late check restarts the count so waking from sleep can't kill a healthy sensor. Tested with the real supervisor in the privileged suite (`supervisor_kills_a_stopped_sensor`: an exec was held 11.5 s).

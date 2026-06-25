**English** · [Русский](README.ru.md)

# scan-webshells.py — webshell scanner & disinfector

Find, quarantine and disinfect web shells / PHP loaders after a server compromise.
It walks the tree **itself** (no dependency on `xargs` or argument-list length),
scans **every file by content** (not just by extension), uses **all CPU cores**,
**streams findings immediately**, and shows progress.

Output is **bilingual**: the language is auto-detected from `$LANG`, or forced with `--lang en|ru`.

---

## Quick start

```bash
# 1. See what is infected (changes nothing, uses all cores, names stream live)
python3 scan-webshells.py /var/www | tee found.txt

# 2. PREVIEW disinfect + quarantine — see the plan, touch nothing   ← do this first
python3 scan-webshells.py /var/www --quarantine /root/Q --clean-index --dry-run | tee plan.txt

# 3. FOR REAL: disinfect index.php + move standalone shells to quarantine
python3 scan-webshells.py /var/www --quarantine /root/Q --clean-index | tee clean.log
```

Requires only Python 3 (standard library, no external packages).

---

## Flags

| Flag | What it does |
|---|---|
| `path` | directory or file to scan (default: current) |
| `--quarantine DIR` | move **standalone shells** into `DIR` (paths preserved) |
| `--clean-index` | strip the injected block from infected `index.php` (backup to `.bak`) |
| `--dry-run` | show what *would* be done — **change nothing** |
| `--quiet` | no progress indicator (for cron/logs) |
| `-j N`, `--jobs N` | number of parallel processes (default = CPU cores) |
| `--lang en\|ru` | output language (default: auto from `$LANG`) |
| `-h`, `--help` | help |

---

## Output & progress

- **Findings print in real time** (to `stdout`) as soon as they are discovered — no need to wait
  for the scan to finish:
  ```
  === FINDINGS (streamed as discovered) ===
  [INJECT] /var/www/.../index.php   =>  goto loader (family A)
  [FULL]   /var/www/.../accesson.php =>  accesson backdoor
  ```
- **Progress** goes to `stderr` as a single self-overwriting line with a percentage:
  ```
  [661800/1412292 46% found:95] 32 cores
  Done: finished, found 312
  ```
- Progress **auto-disables** when output is not a live terminal (`| tee`, `> file`, `| grep`),
  so it never pollutes the findings. Force it off with `--quiet`.
- **Ctrl+C** stops cleanly: it prints "INTERRUPTED … found N" with no traceback; on interruption
  the actions (`--quarantine`/`--clean-index`) are **not** run (the list is incomplete). For a real
  run, let the scan finish.

---

## Common invocations

```bash
# Just the matched files (no action blocks)
python3 scan-webshells.py /var/www --dry-run | grep -E '^\[(FULL|INJECT)\]'

# Disinfect index.php only (don't quarantine the rest)
python3 scan-webshells.py /var/www --clean-index

# Quarantine standalone shells only (leave index.php alone)
python3 scan-webshells.py /var/www --quarantine /root/Q

# Limit load (busy prod — 8 cores instead of 32)
python3 scan-webshells.py /var/www -j 8

# Old single-threaded mode (debug / comparison)
python3 scan-webshells.py /var/www --jobs 1

# Russian output
python3 scan-webshells.py /var/www --lang ru
```

---

## Recommended order on production

```bash
# 1. review the plan (write to a file — full list survives even if the terminal closes)
python3 scan-webshells.py /var/www --quarantine /root/Q --clean-index --dry-run | tee /root/plan.txt

# 2. execute (let it finish — do NOT interrupt)
python3 scan-webshells.py /var/www --quarantine /root/Q --clean-index | tee /root/clean.log

# 3. verify the sites still work

# 4. only then remove backups and quarantine
find /var/www -name '*.bak' -newermt '-1 hour'   # check first what would be deleted
```

On large trees (millions of files) the scan takes a few minutes even on 32 cores —
names stream in real time, so you can see it is alive.

---

## How findings are classified: FULL vs INJECT

- **`[FULL]`** — the **whole file is malware** (`accesson.php`, `cache.php`, `w.php`, `.tmp`,
  media stubs `.ico/.gif/.wma/.wmv`, BOM webshells, …). `--quarantine` takes these (move = backup).
- **`[INJECT]`** — a **legit site file with a prepended block** (e.g. the main `index.php`,
  `vendor/composer/autoload_real.php`). `--quarantine` **leaves it alone**; `--clean-index`
  removes only the malicious leading `<?php…?>` block(s) and writes the original to `.bak`.

The two sets do not overlap — `--clean-index` and `--quarantine` can be run together.

---

## Forensics: file dates & manifest

`--quarantine` preserves **mtime** (when the file was written / appeared) during the move and
writes a CSV manifest `_quarantine_manifest.csv` into the quarantine directory:

```
original_path,mtime,ctime,size,signatures
/var/www/.../accesson.php,2026-05-12 03:41:09,2026-05-12 03:41:09,212,accesson backdoor
```

The modification date is also shown inline: `QUARANTINE: …/shell.php  [modified: 2026-05-12 03:41:09]`.

Notes:
- **mtime** is the key "when did the file appear" signal — it is moved without change;
- **ctime** (inode change time) changes on any move/copy — so it is captured and written to the
  manifest **before** the move;
- mtime can be backdated by the attacker (`touch`), so cross-check with web-server logs and the
  neighbouring files in the same directory.

---

## What is detected

The scanner is tuned for an observed kit and catches several families:

- goto-obfuscated loaders (range injection, hidden labels, hex/octal strings);
- `Sy1Lz`-packed shells (multi-layer gzinflate/base64);
- WSO / FilesMan (`Watching webshell`, box-drawing variable names);
- xleet shells (`//Pass: xleet`);
- the `accesson.php` mini-backdoor (`eval(base64_decode($_REQUEST))` + upload);
- AES-gated file managers (`pw_name_*`);
- base64 / `zip://` includes of media stubs;
- WordPress-style disguise with `eval(pre_term_name())`;
- BOM webshells (double BOM + `@session_start`);
- micro-comment `/*-…-*/` obfuscation and hex-encoded superglobals;
- PHP hidden in media/`.txt` files (only when dangerous functions are present), and `.zip`
  archives containing a `.tmp` loader;
- the Joomla campaign: the `$zym_decrypt` re-infector in `vendor/composer/autoload_real.php`
  plus file managers dropped into surname-named dirs (`zhou/zheng/wu/...`) with a PHP-re-enabling
  `.htaccess`; ROT13 and Chinese shells, `EVAL()` obfuscation, unauthenticated Uploadify
  uploaders, and user input passed directly into `eval/system`.

> **Composer autoloaders are scanned even inside `vendor/`** (`autoload_real.php`,
> `ClassLoader.php`, …) — a classic re-infector target that runs on every request. The rest of
> `vendor/`, plus `node_modules/` and `.git/`, are skipped for speed.

Scanning is **by content**, so a shell named `logo.png` or a file with no extension is found too.
The first 3 MB of each file is read (loader injections are always at the top of the file).

---

## False positives

Heuristics are tuned not to be noisy on large mixed trees:

- WSO/FilesMan: the string `Watching webshell` is matched everywhere, but the box-drawing
  variables `$▛` are matched **only in PHP files** — otherwise the byte `▛` floods on JPEGs and
  other binaries;
- `/*-` obfuscation is checked **only in PHP files** (by extension or starting with `<?php`) — so
  binaries and JS libraries (prototype.js, …) no longer trigger it;
- "PHP inside media/txt" fires only when `<?php` is **at the top of the file** (first 200 bytes)
  **and** a dangerous function is present — so syntax highlighters (codemirror), HTMLPurifier and
  templates with `<?php` deep in the text are not flagged;
- the legit Akeeba installer is whitelisted.

If something is still flagged wrongly, you can see it by the signature label in the output;
exclude such files or edit the `SIG` / `WHITELIST` lists at the top of the script.

---

## Important warnings

- Keep the quarantine dir (`/root/Q`) **outside** the scanned tree, not inside `/var/www`.
- Delete `.bak` files and the quarantine **after** verifying the sites still work.
- Files may be `chmod 444` (a malware trick) — the script drops read-only itself. If the files are
  not owned by you (e.g. `www-data`), run it via `sudo`.
- This is an **RCE compromise**. Besides cleaning files: rotate DB and API passwords/keys, check
  `crontab`, recent files in `uploads/` and `assets/images*/`, and diff the site code against
  git/backups.

---

## Limitations

- The signature detector is tuned for a specific set of families. For fundamentally different
  malware, add signatures to the `SIG` list at the top of the script.
- The actions (`--quarantine`, `--clean-index`) run single-threaded (only a handful of files);
  only scanning is parallelized.

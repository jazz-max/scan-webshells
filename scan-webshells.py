#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Webshell / loader scanner and index.php disinfector.  |  Сканер вебшеллов и лечилка index.php.

Walks the tree itself — no dependency on xargs or argument-list length.
Bilingual output: English by default, Russian via --lang ru (auto-detected from $LANG).

Modes:
  python3 scan-webshells.py PATH                  — scan only (changes nothing)
  python3 scan-webshells.py PATH --quarantine DIR — move STANDALONE shells into DIR (paths preserved)
  python3 scan-webshells.py PATH --clean-index    — strip injected block from infected index.php
  ... --dry-run                                   — show what would be done, touch nothing

Safety model:
  * Files split into FULL (whole file is malware) and INJECT (legit file with a prepended block).
  * --quarantine touches only FULL (move = backup). INJECT is left in place (it is real site code).
  * --clean-index touches only INJECT: removes leading malicious <?php...?> block(s),
    keeps the rest, writes a .bak next to the file first.
"""
import os, re, sys, argparse, shutil, csv
from datetime import datetime
from concurrent.futures import ProcessPoolExecutor

# ---- localization (labels/UI are written in English; RU maps to Russian) ----
LANG = 'ru' if (os.environ.get('LC_ALL') or os.environ.get('LANG') or '').lower().startswith('ru') else 'en'
RU = {
    # signature labels
    'WP-eval injection': 'WP-eval инъекция',
    'goto loader (family A)': 'goto-загрузчик A',
    'loader A (hash)': 'загрузчик A (хеш)',
    'Sy1Lz packer (family B)': 'Sy1Lz-упаковщик B',
    'WSO/FilesMan': 'WSO/FilesMan',
    'xleet shell': 'xleet шелл',
    'accesson backdoor': 'accesson бэкдор',
    'AES file manager': 'AES файл-менеджер',
    'base64 include stub': 'base64-инклюд стаб',
    'BOM webshell': 'BOM-вебшелл',
    'range() injection': 'range инъекция',
    'zip:// loader': 'zip:// загрузчик',
    'hex-obfuscated superglobal/zip': 'hex-обфускация суперглобала/zip',
    'zym_decrypt loader (Joomla)': 'zym_decrypt загрузчик (Joomla)',
    'ROT13-obfuscated shell': 'ROT13-обфускация шелла',
    'EVAL obfuscation': 'EVAL-обфускация',
    'Chinese webshell': 'китайский шелл',
    'webshell (file manager)': 'веб-шелл (file manager)',
    'htaccess PHP re-enabler': 'htaccess php-реактиватор',
    'unauthenticated uploader (Uploadify)': 'непроверенный аплоадер (Uploadify)',
    'user input directly into eval/system': 'ввод напрямую в eval/system',
    'PHP inside media/txt': 'PHP внутри медиа/txt',
    'comment obfuscation /*-': 'комментарий-обфускация /*-',
    'zip archive with .tmp loader': 'zip-архив с .tmp-загрузчиком',
    # UI strings
    'Indexing tree... files: {n}': 'Индексирую дерево... файлов: {n}',
    '[{i}/{total} {pct}% found:{found}] {tail}': '[{i}/{total} {pct}% найдено:{found}] {tail}',
    'cores': 'ядер',
    'Done: finished, found {n}': 'Готово: завершено, найдено {n}',
    'INTERRUPTED: stopped, found {n}': 'ПРЕРВАНО: остановлено, найдено {n}',
    '=== FINDINGS (streamed as discovered) ===': '=== НАЙДЕНО (выводится по мере обнаружения) ===',
    'TOTAL: {n}  (injections: {inj}, standalone shells: {full})':
        'ИТОГО: {n}  (инъекций: {inj}, цельных шеллов: {full})',
    'Scan INTERRUPTED (Ctrl+C) — list incomplete. Actions (--quarantine/--clean-index) skipped.':
        'Сканирование ПРЕРВАНО (Ctrl+C) — список неполный. Действия (--quarantine/--clean-index) пропущены.',
    '=== QUARANTINE ===': '=== КАРАНТИН ===',
    '=== DISINFECT index.php ===': '=== ЛЕЧЕНИЕ index.php ===',
    '(scan only; add --quarantine DIR and/or --clean-index to act)':
        '(только сканирование; для действий добавьте --quarantine DIR и/или --clean-index)',
    'SKIP (injection, use --clean-index): {p}': 'ПРОПУСК (инъекция, лечите --clean-index): {p}',
    '{dry}QUARANTINE: {p}  [modified: {ts}]  ->  {dest}': '{dry}КАРАНТИН: {p}  [изменён: {ts}]  ->  {dest}',
    'ERROR: {e}': 'ОШИБКА: {e}',
    'Manifest with dates: {m}': 'Манифест с датами: {m}',
    'could not write manifest: {e}': 'не удалось записать манифест: {e}',
    'Quarantined: {moved}; skipped INJECT: {skipped}; errors: {errors}':
        'В карантин: {moved}; пропущено INJECT: {skipped}; ошибок: {errors}',
    '{dry}DISINFECT: {p}  (removing bytes {start}..{end}, backup -> {p}.bak)':
        '{dry}ЛЕЧЕНИЕ: {p}  (вырезаю байты {start}..{end}, бэкап -> {p}.bak)',
    'Disinfected injections: {cleaned}; errors: {errors}; standalone shells (need --quarantine): {full}':
        'Вылечено инъекций: {cleaned}; ошибок: {errors}; цельных шеллов (нужен --quarantine): {full}',
    # argparse help
    'Webshell scanner / index.php disinfector.': 'Сканер вебшеллов / лечилка index.php.',
    'directory or file to scan': 'каталог или файл для сканирования',
    'move standalone shells into DIR': 'перенести цельные шеллы в DIR',
    'strip injection from infected index.php': 'вырезать инъекцию из заражённых index.php',
    'show actions only, change nothing': 'только показать действия, не менять файлы',
    'do not print the progress indicator': 'не выводить индикатор прогресса',
    'number of parallel processes (default = CPU cores)': 'число параллельных процессов (по умолчанию = число ядер)',
    'output language (default: auto from $LANG)': 'язык вывода (по умолчанию: авто из $LANG)',
}


def t(s):
    """Translate a UI string/label to the active language (English passthrough)."""
    return RU.get(s, s) if LANG == 'ru' else s


# ---- family signatures (any match => suspected malware) ----
SIG = [
 (re.compile(rb'function pre_term_name|eval\(\s*\$wpautop'),                'WP-eval injection'),
 (re.compile(rb'GICqYxy7yUCHA9p|iHhTWFa3cybb|DjNLICRNUM0w|xf6G86youSZe6Li|tuxbc30YFrFqnMY|lFS_yfY4UdIp|m3hudrwXaCOlP|MC03w1EJuUnte'), 'goto loader (family A)'),
 (re.compile(rb'461c241a2379da8be0c289562d4a056a|5a4b81154c9d50b26e8809c9b8dd5b61|ef8669e065e8af919f|179f41ade4afaefd90500d7321ceb50e|961dedfa0fc1f3c36bd89d9e43de8bec|df53277724b58df978dd1c6264fb70879'), 'loader A (hash)'),
 (re.compile(rb'Sy1LzNFQ'),                                                 'Sy1Lz packer (family B)'),
 (re.compile(rb'Watching webshell'),                                        'WSO/FilesMan'),
 (re.compile(rb'//Pass: xleet|59e8d97dbcc1d0f65dea6ecd0e9fbe39'),           'xleet shell'),
 (re.compile(rb'17028f487cb2a84607646da3ad3878ec|echo\s*409723\s*\*\s*20'), 'accesson backdoor'),
 (re.compile(rb'pw_name_32268|qosZnZCVKkk'),                                'AES file manager'),
 (re.compile(rb'(?:include|require)(?:_once)?\s*\(?\s*base64_decode'),       'base64 include stub'),
 (re.compile(rb'^\xef\xbb\xbf\xc3\xaf\xc2\xbb\xc2\xbf'),                     'BOM webshell'),
 (re.compile(rb'@session_start\(\);\s*@set_time_limit\(0\);'),              'BOM webshell'),
 (re.compile(rb'\(\s*["\']~["\']\s*,\s*["\']\s["\']\s*\)'),                 'range() injection'),
 (re.compile(rb'zip://[^"\']{0,40}\.tmp'),                                  'zip:// loader'),
 # hex/octal-escaped superglobals — legit code never writes these (sup/index.php, loaders)
 (re.compile(rb'\\137\\x52\\x45|\\x5f\\x52\\x45\\x51|\\x52\\x45\\x51\\x55\\x45\\x53\\x54|\\x5f\\x50\\x4f\\x53\\x54|\\x5f\\x43\\x4f\\x4f\\x4b|\\x5f\\x53\\x45\\x52\\x56|\\x7a\\x69\\x70\\x3a'), 'hex-obfuscated superglobal/zip'),
 # --- Joomla campaign (autoload re-infector + dropped file managers in surname-dirs) ---
 (re.compile(rb'zym_decrypt'),                                              'zym_decrypt loader (Joomla)'),
 (re.compile(rb'cebp_bcra|furyy_rkrp|cnffgueh|flfgrz\b|cnffgue'),           'ROT13-obfuscated shell'),  # proc_open/shell_exec/passthru/system in rot13
 (re.compile(rb'EVAL\s*\('),                                               'EVAL obfuscation'),         # uppercase = evades naive grep
 (re.compile(rb'\xe7\xb3\xbb\xe7\xbb\x9f\xe7\xbb\xb4\xe6\x8a\xa4'),         'Chinese webshell'),         # 系统维护 (系统维护工具)
 (re.compile(rb'class MediaLibraryManager|Advanced Shell|Secure File Manager|private\s+\$cp\s*,\s*\$rp\s*,\s*\$dp|x9666'), 'webshell (file manager)'),
 (re.compile(rb'(?s)RewriteEngine\s+off.{0,200}Require all granted'),       'htaccess PHP re-enabler'),
 (re.compile(rb"""\$_FILES\[['"]Filedata['"]\]|_REQUEST\[['"]folder['"]\]"""), 'unauthenticated uploader (Uploadify)'),
 # user input passed DIRECTLY into an executing function — high-signal RCE (few false positives)
 (re.compile(rb'(?:eval|assert|system|shell_exec|passthru|proc_open|popen|pcntl_exec|create_function)\s*\(\s*@?\s*(?:base64_decode\s*\(\s*|stripslashes\s*\(\s*|trim\s*\(\s*)*\$_(?:GET|POST|REQUEST|COOKIE)'), 'user input directly into eval/system'),
]
MEDIA_EXT = ('.ico','.gif','.wma','.wmv','.jpg','.jpeg','.png','.bmp','.txt','.css','.js')
PHP_EXT = ('.php','.php3','.php4','.php5','.php7','.phtml','.phps','.inc','.phar','.module','.tmp')
WHITELIST = (re.compile(rb'AKEEBA KICKSTART|Akeeba\\Engine|akeeba\.com'),)  # legit Akeeba installer
# "dangerous" constructs — so PHP-in-media/txt counts as a shell only when present
DANGER = re.compile(rb'eval\s*\(|assert\s*\(|base64_decode|gzinflate|gzuncompress|str_rot13'
                    rb'|shell_exec|passthru|popen|proc_open|system\s*\('
                    rb'|\$_(?:POST|GET|REQUEST|COOKIE|SERVER)|create_function'
                    rb'|move_uploaded_file|session_start|preg_replace\s*\(')
SKIP_FULL = ('node_modules', '.git')   # skipped entirely
# vendor is skipped for size, BUT composer autoloaders are always checked
# (autoload_real.php is a classic re-infector target, executed on every request)
COMPOSER_FILES = {'autoload_real.php', 'autoload_static.php', 'autoload_classmap.php',
                  'autoload_namespaces.php', 'autoload_psr4.php', 'autoload_files.php',
                  'autoload.php', 'ClassLoader.php', 'InstalledVersions.php'}

# markers of an INJECTED loader block (used to recognise an INJECT prepend)
LOADER_IN_BLOCK = re.compile(
    rb'goto\s+[A-Za-z0-9_]{6,}'                       # goto spaghetti
    rb'|GICqYxy7yUCHA9p|tuxbc30YFrFqnMY|iHhTWFa3cybb|DjNLICRNUM0w|xf6G86youSZe6Li'
    rb'|metaphone\s*\('                                # family A marker
    rb'|\(\s*["\']~["\']\s*,\s*["\']\s["\']\s*\)'      # range("~"," ")
    rb'|"\\176"|"\\x7e"'                               # hex form of "~"
    rb'|zym_decrypt'                                   # Joomla autoload re-infector
)
PHP_OPEN = re.compile(rb'<\?php', re.I)


def _php_open_in_head(data, limit=200):
    """
    True if the first `limit` bytes contain a REAL opening <?php tag, not a commented
    one ("// <?php !! fool phpDocumentor", "* <?php", "# <?php"). Filters out legit
    joomla.javascript.js and friends.
    """
    for m in re.finditer(rb'<\?php', data[:limit]):
        ls = data.rfind(b'\n', 0, m.start()) + 1
        prefix = data[ls:m.start()].lstrip(b'\xef\xbb\xbf\xc3\xaf\xc2\xbb \t\r\n')
        if not (prefix.startswith(b'//') or prefix.startswith(b'*')
                or prefix.startswith(b'#') or prefix.startswith(b'/*')):
            return True
    return False


def classify(data, ext):
    """Return a list of matched signature labels (English, canonical) or None."""
    if any(w.search(data) for w in WHITELIST):
        return None
    hits = set()
    for rx, name in SIG:
        if rx.search(data):
            hits.add(name)
    # PHP file by extension or by starting with <?php (BOM-aware)
    starts_php = data[:80].lstrip(b'\xef\xbb\xbf\xc3\xaf\xc2\xbb \t\r\n').startswith(b'<?php')
    php_file = ext in PHP_EXT or starts_php
    # PHP hidden in media/txt: <?php must be a REAL opening tag at the top of the file
    # (not inside a JS/CSS comment like "// <?php !! fool phpDocumentor") + a dangerous call.
    if ext in MEDIA_EXT and _php_open_in_head(data) and DANGER.search(data):
        hits.add('PHP inside media/txt')
    # micro-comment /*-...-*/ obfuscation — PHP files only (binaries gave false positives)
    if php_file and data.count(b'/*-') >= 3:
        hits.add('comment obfuscation /*-')
    # WSO/FilesMan with box-drawing variable names ($▛ $▘ $▜) — PHP files only
    # (the bare byte ▛ is common in JPEG/binaries)
    if php_file and re.search(rb'\$\xe2\x96[\x98\x9b\x9c\x9d]', data):
        hits.add('WSO/FilesMan')
    # zip archive containing a .tmp loader
    if ext == '.zip' and b'.tmp' in data:
        hits.add('zip archive with .tmp loader')
    return sorted(hits) or None


def injected_block(data):
    """
    If the file = malicious prepend + legit code, return (start, end, new_content),
    else None. Strips ALL consecutive leading malicious <?php...?> blocks (an injection
    may span several blocks, like zym_decrypt in autoload_real.php).
    """
    WS = b'\xef\xbb\xbf \t\r\n'
    first = PHP_OPEN.search(data)
    if not first or data[:first.start()].strip(WS):
        return None                       # foreign data before the injection
    offset = first.start()
    removed = False
    while True:
        m = PHP_OPEN.search(data, offset)
        if not m or data[offset:m.start()].strip(WS):
            break                         # next thing is not a back-to-back <?php block — real code
        end = data.find(b'?>', m.end())
        if end == -1:
            break
        if not LOADER_IN_BLOCK.search(data[m.start():end + 2]):
            break                         # this block is clean => start of the real code
        offset = end + 2
        removed = True
    if not removed:
        return None
    tail = data[offset:]
    if len(tail.strip()) < 30 or b'<?php' not in tail:
        return None                       # no code after the blocks => FULL shell, not INJECT
    new_content = data[:first.start()] + tail.lstrip(b'\r\n')
    return (first.start(), offset, new_content)


def _progress(msg):
    """Single-line indicator on stderr (does not pollute stdout findings)."""
    line = msg[:100].ljust(100)
    sys.stderr.write('\r' + line)
    sys.stderr.flush()


def scan_file(p):
    """Process one file. Returns (path, hits, inj) or None. For the process pool."""
    try:
        with open(p, 'rb') as f:
            data = f.read(3_000_000)
    except Exception:
        return None
    hits = classify(data, os.path.splitext(p)[1].lower())
    if not hits:
        return None
    return (p, hits, injected_block(data))


def list_files(root, progress=True):
    """Fast tree walk -> list of paths (honouring skipped directories)."""
    if os.path.isfile(root):       # allow scanning a single file
        return [root]
    files = []
    for dp, dirs, fs in os.walk(root):
        parts = dp.replace(os.sep, '/').split('/')
        if any(s in parts for s in SKIP_FULL):
            dirs[:] = []                       # node_modules/.git — skip entirely
            continue
        if 'vendor' in parts:                  # inside vendor read only composer autoloaders
            for fn in fs:
                if fn in COMPOSER_FILES:
                    files.append(os.path.join(dp, fn))
            continue                           # do not prune: need to reach vendor/composer/
        for fn in fs:
            files.append(os.path.join(dp, fn))
        if progress and len(files) % 2000 < len(fs) + 1:
            _progress(t('Indexing tree... files: {n}').format(n=len(files)))
    return files


def scan(root, progress=True, jobs=1, on_find=None):
    """
    Return (findings, interrupted). on_find(r) is called immediately on each find
    (streaming output). interrupted=True if stopped via Ctrl+C.
    """
    files = list_files(root, progress)
    total = len(files)
    out = []
    interrupted = False

    def handle(r, i, tail):
        if r:
            out.append(r)
            if on_find:
                if progress:                       # clear the progress line before printing a path
                    sys.stderr.write('\r' + ' ' * 100 + '\r'); sys.stderr.flush()
                on_find(r)
        if progress and i % 200 == 0:
            _progress(t('[{i}/{total} {pct}% found:{found}] {tail}').format(
                i=i, total=total, pct=i * 100 // max(total, 1), found=len(out), tail=tail))

    try:
        if jobs <= 1:
            for i, p in enumerate(files):
                handle(scan_file(p), i, os.path.dirname(p))
        else:
            chunk = max(1, min(256, total // (jobs * 8) or 1))
            with ProcessPoolExecutor(max_workers=jobs) as ex:
                for i, r in enumerate(ex.map(scan_file, files, chunksize=chunk)):
                    handle(r, i, f"{jobs} {t('cores')}")
    except KeyboardInterrupt:
        interrupted = True

    if progress:
        key = 'INTERRUPTED: stopped, found {n}' if interrupted else 'Done: finished, found {n}'
        _progress(t(key).format(n=len(out)))
        sys.stderr.write('\n'); sys.stderr.flush()
    return out, interrupted


def _force_writable(path):
    """Drop read-only (malware often sets chmod 444) so the file can be edited/moved."""
    try:
        os.chmod(path, 0o644)
    except OSError:
        pass


def _fmt_ts(ts):
    try:
        return datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')
    except Exception:
        return '?'


def do_quarantine(findings, qdir, root, dry):
    qdir = os.path.abspath(qdir)
    moved = skipped = errors = 0
    rows = []                              # for the forensic manifest
    dpfx = '[dry] ' if dry else ''
    for p, hits, inj in findings:
        if inj:                            # INJECT — must not move, disinfected separately
            print('  ' + t('SKIP (injection, use --clean-index): {p}').format(p=p))
            skipped += 1
            continue
        try:                               # capture times BEFORE moving (this is "when the file appeared")
            st = os.stat(p)
            mt, at, ct, size = st.st_mtime, st.st_atime, st.st_ctime, st.st_size
        except OSError:
            mt = at = ct = 0; size = -1
        rel = os.path.relpath(p, root)     # path relative to the scan root
        dest = os.path.join(qdir, rel)
        print('  ' + t('{dry}QUARANTINE: {p}  [modified: {ts}]  ->  {dest}').format(
            dry=dpfx, p=p, ts=_fmt_ts(mt), dest=dest))
        if not dry:
            try:
                os.makedirs(os.path.dirname(dest), exist_ok=True)
                while os.path.exists(dest):
                    dest += '.dup'
                shutil.move(p, dest)       # rename / copy2+unlink — mtime and atime preserved
                if mt:
                    os.utime(dest, (at, mt))   # guarantee original times on the moved file
            except OSError as e:
                print('    ' + t('ERROR: {e}').format(e=e))
                errors += 1
                continue
        rows.append([p, _fmt_ts(mt), _fmt_ts(ct), size, '; '.join(hits)])
        moved += 1
    # forensic manifest: path + when the file was modified/appeared (survives the move)
    if rows and not dry:
        manifest = os.path.join(qdir, '_quarantine_manifest.csv')
        try:
            os.makedirs(qdir, exist_ok=True)
            new = not os.path.exists(manifest)
            with open(manifest, 'a', newline='', encoding='utf-8') as f:
                w = csv.writer(f)
                if new:
                    w.writerow(['original_path', 'mtime', 'ctime', 'size', 'signatures'])
                w.writerows(rows)
            print('\n' + t('Manifest with dates: {m}').format(m=manifest))
        except OSError as e:
            print('  ' + t('could not write manifest: {e}').format(e=e))
    print('\n' + t('Quarantined: {moved}; skipped INJECT: {skipped}; errors: {errors}').format(
        moved=moved, skipped=skipped, errors=errors))


def do_clean_index(findings, dry):
    cleaned = errors = 0
    dpfx = '[dry] ' if dry else ''
    for p, hits, inj in findings:
        if not inj:                   # FULL shell — nothing to disinfect, must be removed/quarantined
            continue
        start, end, new_content = inj
        print('  ' + t('{dry}DISINFECT: {p}  (removing bytes {start}..{end}, backup -> {p}.bak)').format(
            dry=dpfx, p=p, start=start, end=end))
        if not dry:
            try:
                shutil.copy2(p, p + '.bak')
                _force_writable(p)
                with open(p, 'wb') as f:
                    f.write(new_content)
            except OSError as e:
                print('    ' + t('ERROR: {e}').format(e=e))
                errors += 1
                continue
        cleaned += 1
    full = sum(1 for _, _, inj in findings if not inj)
    print('\n' + t('Disinfected injections: {cleaned}; errors: {errors}; standalone shells (need --quarantine): {full}').format(
        cleaned=cleaned, errors=errors, full=full))


def main():
    global LANG
    ap = argparse.ArgumentParser(description=t('Webshell scanner / index.php disinfector.'))
    ap.add_argument('path', nargs='?', default='.', help=t('directory or file to scan'))
    ap.add_argument('--quarantine', metavar='DIR', help=t('move standalone shells into DIR'))
    ap.add_argument('--clean-index', action='store_true', help=t('strip injection from infected index.php'))
    ap.add_argument('--dry-run', action='store_true', help=t('show actions only, change nothing'))
    ap.add_argument('--quiet', action='store_true', help=t('do not print the progress indicator'))
    ap.add_argument('-j', '--jobs', type=int, default=os.cpu_count() or 1,
                    help=t('number of parallel processes (default = CPU cores)'))
    ap.add_argument('--lang', choices=('en', 'ru'), help=t('output language (default: auto from $LANG)'))
    args = ap.parse_args()
    if args.lang:
        LANG = args.lang

    # progress only to a live terminal; auto-off on pipe/redirect so it never pollutes output
    show_progress = (not args.quiet) and sys.stderr.isatty()

    def printer(r):
        p, hits, inj = r
        tag = '[INJECT]' if inj else '[FULL]  '
        print(f"{tag} {p}  =>  {', '.join(t(h) for h in hits)}", flush=True)

    print(t('=== FINDINGS (streamed as discovered) ==='))
    findings, interrupted = scan(args.path, progress=show_progress,
                                 jobs=args.jobs, on_find=printer)
    n_inj = sum(1 for _, _, inj in findings if inj)
    print('\n' + t('TOTAL: {n}  (injections: {inj}, standalone shells: {full})').format(
        n=len(findings), inj=n_inj, full=len(findings) - n_inj))
    if interrupted:
        print('⚠️  ' + t('Scan INTERRUPTED (Ctrl+C) — list incomplete. Actions (--quarantine/--clean-index) skipped.'))
        return

    if args.quarantine:
        print('\n' + t('=== QUARANTINE ==='))
        do_quarantine(findings, args.quarantine, args.path, args.dry_run)
    if args.clean_index:
        print('\n' + t('=== DISINFECT index.php ==='))
        do_clean_index(findings, args.dry_run)
    if not args.quarantine and not args.clean_index:
        print('\n' + t('(scan only; add --quarantine DIR and/or --clean-index to act)'))


if __name__ == '__main__':
    main()

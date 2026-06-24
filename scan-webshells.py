#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Сканер вебшеллов/загрузчиков и лечилка заражённых index.php.
Обходит дерево сам — не зависит от xargs и длины списка аргументов.

Режимы:
  python3 scan-webshells.py PATH                  — только показать находки (ничего не меняет)
  python3 scan-webshells.py PATH --quarantine DIR — перенести ЦЕЛЬНЫЕ шеллы в DIR (с сохранением путей)
  python3 scan-webshells.py PATH --clean-index    — вырезать вставленный блок из заражённых index.php
  ... --dry-run                                   — показать, что было бы сделано, но не трогать файлы

Логика безопасности:
  * Файлы делятся на FULL (файл целиком — вирус) и INJECT (легитимный файл с инъекцией сверху).
  * --quarantine трогает только FULL (перенос = бэкап). INJECT не двигает (там код сайта).
  * --clean-index трогает только INJECT: вырезает первый вредоносный <?php...?>-блок,
    оставляя остальной код. Перед правкой делает .bak рядом с файлом.
"""
import os, re, sys, argparse, shutil, csv
from datetime import datetime
from concurrent.futures import ProcessPoolExecutor

# ---- сигнатуры семейств (любая => подозрение на вирус) ----
SIG = [
 (re.compile(rb'function pre_term_name|eval\(\s*\$wpautop'),                'WP-eval инъекция'),
 (re.compile(rb'GICqYxy7yUCHA9p|iHhTWFa3cybb|DjNLICRNUM0w|xf6G86youSZe6Li|tuxbc30YFrFqnMY|lFS_yfY4UdIp|m3hudrwXaCOlP|MC03w1EJuUnte'), 'goto-загрузчик A'),
 (re.compile(rb'461c241a2379da8be0c289562d4a056a|5a4b81154c9d50b26e8809c9b8dd5b61|ef8669e065e8af919f|179f41ade4afaefd90500d7321ceb50e|961dedfa0fc1f3c36bd89d9e43de8bec|df53277724b58df978dd1c6264fb70879'), 'загрузчик A (хеш)'),
 (re.compile(rb'Sy1LzNFQ'),                                                 'Sy1Lz-упаковщик B'),
 (re.compile(rb'Watching webshell'),                                        'WSO/FilesMan'),
 (re.compile(rb'//Pass: xleet|59e8d97dbcc1d0f65dea6ecd0e9fbe39'),           'xleet шелл'),
 (re.compile(rb'17028f487cb2a84607646da3ad3878ec|echo\s*409723\s*\*\s*20'), 'accesson бэкдор'),
 (re.compile(rb'pw_name_32268|qosZnZCVKkk'),                                'AES файл-менеджер'),
 (re.compile(rb'(?:include|require)(?:_once)?\s*\(?\s*base64_decode'),       'base64-инклюд стаб'),
 (re.compile(rb'^\xef\xbb\xbf\xc3\xaf\xc2\xbb\xc2\xbf'),                     'BOM-вебшелл'),
 (re.compile(rb'@session_start\(\);\s*@set_time_limit\(0\);'),              'BOM-вебшелл'),
 (re.compile(rb'\(\s*["\']~["\']\s*,\s*["\']\s["\']\s*\)'),                 'range инъекция'),
 (re.compile(rb'zip://[^"\']{0,40}\.tmp'),                                  'zip:// загрузчик'),
 # hex/octal-экранированные суперглобалы — легитимный код так не пишет (sup/index.php, загрузчики)
 (re.compile(rb'\\137\\x52\\x45|\\x5f\\x52\\x45\\x51|\\x52\\x45\\x51\\x55\\x45\\x53\\x54|\\x5f\\x50\\x4f\\x53\\x54|\\x5f\\x43\\x4f\\x4f\\x4b|\\x5f\\x53\\x45\\x52\\x56|\\x7a\\x69\\x70\\x3a'), 'hex-обфускация суперглобала/zip'),
 # --- Joomla-кампания (autoload-переинфектор + дроп файл-менеджеров в папках-фамилиях) ---
 (re.compile(rb'zym_decrypt'),                                              'zym_decrypt загрузчик (Joomla)'),
 (re.compile(rb'cebp_bcra|furyy_rkrp|cnffgueh|flfgrz\b|cnffgue'),           'ROT13-обфускация шелла'),  # proc_open/shell_exec/passthru/system в rot13
 (re.compile(rb'EVAL\s*\('),                                               'EVAL-обфускация'),         # верхний регистр = обход наивного grep
 (re.compile(rb'\xe7\xb3\xbb\xe7\xbb\x9f\xe7\xbb\xb4\xe6\x8a\xa4'),         'китайский шелл'),          # 系统维护 (系统维护工具)
 (re.compile(rb'class MediaLibraryManager|Advanced Shell|Secure File Manager|private\s+\$cp\s*,\s*\$rp\s*,\s*\$dp|x9666'), 'веб-шелл (file manager)'),
 (re.compile(rb'(?s)RewriteEngine\s+off.{0,200}Require all granted'),       'htaccess php-реактиватор'),
 # ввод НАПРЯМУЮ в исполняющую функцию — высокосигнальный RCE (мало ложных)
 (re.compile(rb'(?:eval|assert|system|shell_exec|passthru|proc_open|popen|pcntl_exec|create_function)\s*\(\s*@?\s*(?:base64_decode\s*\(\s*|stripslashes\s*\(\s*|trim\s*\(\s*)*\$_(?:GET|POST|REQUEST|COOKIE)'), 'ввод напрямую в eval/system'),
]
MEDIA_EXT = ('.ico','.gif','.wma','.wmv','.jpg','.jpeg','.png','.bmp','.txt','.css','.js')
PHP_EXT = ('.php','.php3','.php4','.php5','.php7','.phtml','.phps','.inc','.phar','.module','.tmp')
WHITELIST = (re.compile(rb'AKEEBA KICKSTART|Akeeba\\Engine|akeeba\.com'),)  # легитимный установщик Akeeba
# «опасные» конструкции — чтобы PHP в медиа/txt считать шеллом только при их наличии
DANGER = re.compile(rb'eval\s*\(|assert\s*\(|base64_decode|gzinflate|gzuncompress|str_rot13'
                    rb'|shell_exec|passthru|popen|proc_open|system\s*\('
                    rb'|\$_(?:POST|GET|REQUEST|COOKIE|SERVER)|create_function'
                    rb'|move_uploaded_file|session_start|preg_replace\s*\(')
SKIP_FULL = ('node_modules', '.git')   # пропускать целиком
# vendor пропускаем по объёму, НО composer-автозагрузчики проверяем всегда
# (autoload_real.php — типичная цель переинфекторов, исполняется на каждом запросе)
COMPOSER_FILES = {'autoload_real.php', 'autoload_static.php', 'autoload_classmap.php',
                  'autoload_namespaces.php', 'autoload_psr4.php', 'autoload_files.php',
                  'autoload.php', 'ClassLoader.php', 'InstalledVersions.php'}

# маркеры именно ВСТАВЛЕННОГО загрузчика (для распознавания INJECT-блока)
LOADER_IN_BLOCK = re.compile(
    rb'goto\s+[A-Za-z0-9_]{6,}'                       # goto-лапша
    rb'|GICqYxy7yUCHA9p|tuxbc30YFrFqnMY|iHhTWFa3cybb|DjNLICRNUM0w|xf6G86youSZe6Li'
    rb'|metaphone\s*\('                                # метка семейства A
    rb'|\(\s*["\']~["\']\s*,\s*["\']\s["\']\s*\)'      # range("~"," ")
    rb'|"\\176"|"\\x7e"'                               # hex-вариант "~"
    rb'|zym_decrypt'                                   # Joomla autoload-переинфектор
)
PHP_OPEN = re.compile(rb'<\?php', re.I)


def _php_open_in_head(data, limit=200):
    """
    True, если в первых `limit` байтах есть НАСТОЯЩИЙ открывающий тег <?php,
    а не закомментированный (JS/CSS-трюк "// <?php !! fool phpDocumentor",
    "* <?php", "# <?php"). Так отсекаются легит joomla.javascript.js и т.п.
    """
    for m in re.finditer(rb'<\?php', data[:limit]):
        ls = data.rfind(b'\n', 0, m.start()) + 1
        prefix = data[ls:m.start()].lstrip(b'\xef\xbb\xbf\xc3\xaf\xc2\xbb \t\r\n')
        if not (prefix.startswith(b'//') or prefix.startswith(b'*')
                or prefix.startswith(b'#') or prefix.startswith(b'/*')):
            return True
    return False


def classify(data, ext):
    """Вернёт список сработавших сигнатур или None."""
    if any(w.search(data) for w in WHITELIST):
        return None
    hits = set()
    for rx, name in SIG:
        if rx.search(data):
            hits.add(name)
    # PHP-файл по расширению или по старту с <?php (с учётом BOM)
    starts_php = data[:80].lstrip(b'\xef\xbb\xbf\xc3\xaf\xc2\xbb \t\r\n').startswith(b'<?php')
    php_file = ext in PHP_EXT or starts_php
    # PHP, спрятанный в медиа/txt: <?php должен быть НАСТОЯЩИМ открывающим тегом в начале файла
    # (не внутри JS/CSS-комментария вроде "// <?php !! fool phpDocumentor") + опасная функция.
    if ext in MEDIA_EXT and _php_open_in_head(data) and DANGER.search(data):
        hits.add('PHP внутри медиа/txt')
    # обфускация микро-комментариями /*-...-*/ — только в PHP-файлах (бинари давали ложь)
    if php_file and data.count(b'/*-') >= 3:
        hits.add('комментарий-обфускация /*-')
    # WSO/FilesMan с именами-псевдографикой ($▛ $▘ $▜) — только в PHP-файлах
    # (голый байт ▛ массово встречается в JPEG/бинарях)
    if php_file and re.search(rb'\$\xe2\x96[\x98\x9b\x9c\x9d]', data):
        hits.add('WSO/FilesMan')
    # zip-архив, содержащий .tmp-загрузчик
    if ext == '.zip' and b'.tmp' in data:
        hits.add('zip-архив с .tmp-загрузчиком')
    return sorted(hits) or None


def injected_block(data):
    """
    Если файл = вредоносная вставка сверху + легитимный код, вернёт кортеж
    (start, end, new_content), иначе None. Снимает ВСЕ идущие подряд в начале
    вредоносные <?php...?> блоки (инъекция может быть из нескольких блоков,
    как у zym_decrypt в autoload_real.php).
    """
    WS = b'\xef\xbb\xbf \t\r\n'
    first = PHP_OPEN.search(data)
    if not first or data[:first.start()].strip(WS):
        return None                       # перед инъекцией есть посторонние данные
    offset = first.start()
    removed = False
    while True:
        m = PHP_OPEN.search(data, offset)
        if not m or data[offset:m.start()].strip(WS):
            break                         # дальше идёт не <?php-блок вплотную — это уже код
        end = data.find(b'?>', m.end())
        if end == -1:
            break
        if not LOADER_IN_BLOCK.search(data[m.start():end + 2]):
            break                         # очередной блок чистый => начало настоящего кода
        offset = end + 2
        removed = True
    if not removed:
        return None
    tail = data[offset:]
    if len(tail.strip()) < 30 or b'<?php' not in tail:
        return None                       # после блоков нет кода => это FULL-шелл, не INJECT
    new_content = data[:first.start()] + tail.lstrip(b'\r\n')
    return (first.start(), offset, new_content)


def _progress(msg):
    """Однострочный индикатор в stderr (не мешает выводу находок в stdout)."""
    line = msg[:100].ljust(100)
    sys.stderr.write('\r' + line)
    sys.stderr.flush()


def scan_file(p):
    """Обработать один файл. Возвращает (path, hits, inj) или None. Для пула процессов."""
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
    """Быстрый обход дерева -> список путей (с учётом пропускаемых каталогов)."""
    files = []
    for dp, dirs, fs in os.walk(root):
        parts = dp.replace(os.sep, '/').split('/')
        if any(s in parts for s in SKIP_FULL):
            dirs[:] = []                       # node_modules/.git — целиком мимо
            continue
        if 'vendor' in parts:                  # внутри vendor читаем только composer-автозагрузчики
            for fn in fs:
                if fn in COMPOSER_FILES:
                    files.append(os.path.join(dp, fn))
            continue                           # не прунить: нужно дойти до vendor/composer/
        for fn in fs:
            files.append(os.path.join(dp, fn))
        if progress and len(files) % 2000 < len(fs) + 1:
            _progress(f"Индексирую дерево... файлов: {len(files)}")
    return files


def scan(root, progress=True, jobs=1, on_find=None):
    """
    Возвращает (findings, interrupted). on_find(r) вызывается сразу при каждой
    находке (потоковый вывод). interrupted=True, если прервано через Ctrl+C.
    """
    files = list_files(root, progress)
    total = len(files)
    out = []
    interrupted = False

    def handle(r, i, tail):
        if r:
            out.append(r)
            if on_find:
                if progress:                       # стереть строку прогресса перед печатью пути
                    sys.stderr.write('\r' + ' ' * 100 + '\r'); sys.stderr.flush()
                on_find(r)
        if progress and i % 200 == 0:
            _progress(f"[{i}/{total} {i*100//max(total,1)}% найдено:{len(out)}] {tail}")

    try:
        if jobs <= 1:
            for i, p in enumerate(files):
                handle(scan_file(p), i, os.path.dirname(p))
        else:
            chunk = max(1, min(256, total // (jobs * 8) or 1))
            with ProcessPoolExecutor(max_workers=jobs) as ex:
                for i, r in enumerate(ex.map(scan_file, files, chunksize=chunk)):
                    handle(r, i, f"{jobs} ядер")
    except KeyboardInterrupt:
        interrupted = True

    if progress:
        state = "ПРЕРВАНО" if interrupted else "Готово"
        _progress(f"{state}: обработка завершена, найдено {len(out)}")
        sys.stderr.write('\n'); sys.stderr.flush()
    return out, interrupted


def _force_writable(path):
    """Снять read-only (малварь часто ставит chmod 444), чтобы файл можно было править/двигать."""
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
    rows = []                              # для forensic-манифеста
    for p, hits, inj in findings:
        if inj:                            # это INJECT — двигать нельзя, лечится отдельно
            print(f"  ПРОПУСК (инъекция, лечите --clean-index): {p}")
            skipped += 1
            continue
        try:                               # снять времена ДО переноса (это и есть «когда появился файл»)
            st = os.stat(p)
            mt, at, ct, size = st.st_mtime, st.st_atime, st.st_ctime, st.st_size
        except OSError:
            mt = at = ct = 0; size = -1
        rel = os.path.relpath(p, root)     # путь относительно корня сканирования
        dest = os.path.join(qdir, rel)
        print(f"  {'[dry] ' if dry else ''}КАРАНТИН: {p}  [изменён: {_fmt_ts(mt)}]  ->  {dest}")
        if not dry:
            try:
                os.makedirs(os.path.dirname(dest), exist_ok=True)
                while os.path.exists(dest):
                    dest += '.dup'
                shutil.move(p, dest)       # rename / copy2+unlink — mtime и atime сохраняются
                if mt:
                    os.utime(dest, (at, mt))   # гарантированно вернуть исходные времена
            except OSError as e:
                print(f"    ОШИБКА: {e}")
                errors += 1
                continue
        rows.append([p, _fmt_ts(mt), _fmt_ts(ct), size, '; '.join(hits)])
        moved += 1
    # forensic-манифест: путь + когда файл изменён/появился (переживает перенос)
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
            print(f"\nМанифест с датами: {manifest}")
        except OSError as e:
            print(f"  не удалось записать манифест: {e}")
    print(f"\nВ карантин: {moved}; пропущено INJECT: {skipped}; ошибок: {errors}")


def do_clean_index(findings, dry):
    cleaned = errors = 0
    for p, hits, inj in findings:
        if not inj:                   # FULL-шелл — лечить нечего, его надо удалять/карантинить
            continue
        start, end, new_content = inj
        print(f"  {'[dry] ' if dry else ''}ЛЕЧЕНИЕ: {p}  (вырезаю байты {start}..{end}, бэкап -> {p}.bak)")
        if not dry:
            try:
                shutil.copy2(p, p + '.bak')
                _force_writable(p)
                with open(p, 'wb') as f:
                    f.write(new_content)
            except OSError as e:
                print(f"    ОШИБКА: {e}")
                errors += 1
                continue
        cleaned += 1
    full = sum(1 for _, _, inj in findings if not inj)
    print(f"\nВылечено index-инъекций: {cleaned}; ошибок: {errors}; "
          f"цельных шеллов (нужен --quarantine): {full}")


def main():
    ap = argparse.ArgumentParser(description='Сканер/лечилка вебшеллов.')
    ap.add_argument('path', nargs='?', default='.', help='каталог для сканирования')
    ap.add_argument('--quarantine', metavar='DIR', help='перенести цельные шеллы в DIR')
    ap.add_argument('--clean-index', action='store_true', help='вырезать инъекцию из заражённых index.php')
    ap.add_argument('--dry-run', action='store_true', help='только показать действия, не менять файлы')
    ap.add_argument('--quiet', action='store_true', help='не выводить индикатор прогресса')
    ap.add_argument('-j', '--jobs', type=int, default=os.cpu_count() or 1,
                    help='число параллельных процессов (по умолчанию = число ядер)')
    args = ap.parse_args()

    # прогресс только в живой терминал; при пайпе/редиректе сам отключается, чтобы не мешать
    show_progress = (not args.quiet) and sys.stderr.isatty()

    def printer(r):
        p, hits, inj = r
        tag = '[INJECT]' if inj else '[FULL]  '
        print(f"{tag} {p}  =>  {', '.join(hits)}", flush=True)

    print("=== НАЙДЕНО (выводится по мере обнаружения) ===")
    findings, interrupted = scan(args.path, progress=show_progress,
                                 jobs=args.jobs, on_find=printer)
    n_inj = sum(1 for _, _, inj in findings if inj)
    print(f"\nИТОГО: {len(findings)}  (INJECT-инъекций: {n_inj}, цельных шеллов: {len(findings)-n_inj})")
    if interrupted:
        print("⚠️  Сканирование ПРЕРВАНО (Ctrl+C) — список неполный. "
              "Действия (--quarantine/--clean-index) пропущены.")
        return

    if args.quarantine:
        print("\n=== КАРАНТИН ===")
        do_quarantine(findings, args.quarantine, args.path, args.dry_run)
    if args.clean_index:
        print("\n=== ЛЕЧЕНИЕ index.php ===")
        do_clean_index(findings, args.dry_run)
    if not args.quarantine and not args.clean_index:
        print("\n(только сканирование; для действий добавьте --quarantine DIR и/или --clean-index)")


if __name__ == '__main__':
    main()

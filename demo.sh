#!/usr/bin/env bash
# Self-contained demo of scan-webshells: builds a throwaway "infected" tree from
# HARMLESS marker files (they only contain detector strings — nothing executes),
# runs the scanner, then cleans up. Safe to run anywhere. Great as a recording target.
set -e
D="$(mktemp -d)"
trap 'rm -rf "$D"' EXIT
mkdir -p "$D/uploads/images" "$D/zhou"

# --- harmless files that match real detector signatures (markers only, no live payload) ---
printf '<?php /* demo */ $a = range("~", " "); /* goto loader marker, harmless */ ?>\n'      > "$D/index.php"
printf '<?php\n// Watching webshell\n// demo marker, harmless\n'                              > "$D/zhou/manager.php"
printf '<?php /* //Pass: xleet  demo marker, harmless */\n'                                   > "$D/zhou/x.php"
printf 'GIF89a<?php /* demo: markers $_POST eval base64_decode, harmless comment */ ?>'       > "$D/uploads/images/logo.gif"
printf '<?php $_FILES["Filedata"]; /* unauthenticated uploader marker, harmless */\n'         > "$D/uploads/up.php"
printf '<?php\n// a perfectly legitimate file that uses preg_match() — must NOT be flagged\n'\
'$ok = preg_match("/^[a-z]+$/", $name);\n'                                                    > "$D/legit_helper.php"

echo "### scan-webshells demo — scanning a throwaway infected tree"
echo "### (all sample files are harmless markers; legit_helper.php must stay clean)"
echo
DIR="$(cd "$(dirname "$0")" && pwd)"
python3 "$DIR/scan-webshells.py" "$D" --lang "${1:-en}"
echo
echo "### done — temp tree removed automatically. Nothing was modified on your system."

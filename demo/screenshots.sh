#!/usr/bin/env bash
# Regenerates the images in art/ from the bundle itself. Run it after changing
# the command output or the email, then commit art/.
#
# Needs PHP (with the dev dependencies installed) and a Chrome or Chromium
# binary: set CHROME=/path/to/chrome if it isn't on the PATH.
set -euo pipefail
cd "$(dirname "$0")/.."

CHROME=${CHROME:-$(command -v chromium || command -v chromium-browser || command -v google-chrome || command -v chrome-headless-shell || true)}
[ -x "$CHROME" ] || { echo "Chrome not found; set CHROME=/path/to/chrome" >&2; exit 1; }

rm -rf build
php demo/render.php build
mkdir -p art

shot() { # name, page, window size
    "$CHROME" --headless --no-sandbox --hide-scrollbars --force-device-scale-factor=2 \
        --window-size="$3" --screenshot="art/$1.png" "file://$PWD/build/$2.html" 2>/dev/null
    echo "art/$1.png"
}

shot screenshot-terminal terminal "${TERMINAL_SIZE:-1480,610}"
shot screenshot-mail mail "${MAIL_SIZE:-860,1300}"

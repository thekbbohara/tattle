#!/bin/sh
# Screenshot the demo HTML report: phone and desktop width, final frame.
set -eu
cd "$(dirname "$0")/.."
out=target/shots
mkdir -p "$out"
target/release/tattle demo target/demo-home --html "$out/report.html" >/dev/null 2>&1 || true
chrome=$(command -v google-chrome-stable || command -v google-chrome || command -v chromium || command -v chromium-browser || true)
[ -n "$chrome" ] || { echo "Chrome/Chromium not found" >&2; exit 1; }
url="file://$PWD/$out/report.html#still"
"$chrome" --headless=new --disable-gpu --hide-scrollbars --force-device-scale-factor=2 --window-size=430,1800 --screenshot="$PWD/$out/phone.png" "$url" 2>/dev/null
"$chrome" --headless=new --disable-gpu --hide-scrollbars --window-size=1280,2400 --screenshot="$PWD/$out/desktop.png" "$url" 2>/dev/null
echo "$out/phone.png $out/desktop.png"

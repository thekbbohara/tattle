#!/bin/sh
# Animated GIF of the demo HTML report counting up, for the README.
# Made from `tattle demo` only: fake home, fake logs. Each frame is the demo
# report with the big number set to one step of the page's own ease-out
# count-up, screenshot in #still mode. Needs Chrome/Chromium and ImageMagick.
#   sh scripts/demo-gif.sh [OUT]      (default: docs/tattle-demo.gif)
set -eu
cd "$(dirname "$0")/.."
out=${1:-docs/tattle-demo.gif}
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
target/release/tattle demo "$work/home" --html "$work/report.html" >/dev/null 2>&1 || true
chrome=$(command -v google-chrome-stable || command -v google-chrome || command -v chromium || command -v chromium-browser || true)
[ -n "$chrome" ] || { echo "Chrome/Chromium not found" >&2; exit 1; }
n=$(sed -n 's/.*data-n="\([0-9]*\)".*/\1/p' "$work/report.html")
frames=16
i=0
while [ $i -le $frames ]; do
  v=$(awk -v n="$n" -v i=$i -v f=$frames 'BEGIN { p = i / f; printf "%d", n * (1 - (1 - p) ^ 3) + 0.5 }')
  shown=$(printf "%d" "$v" | sed ':a;s/\B[0-9]\{3\}\>/,&/;ta')
  f="$work/f$(printf %02d $i)"
  sed "s/data-n=\"$n\">[0-9,]*</data-n=\"$n\">$shown</" "$work/report.html" > "$f.html"
  timeout 30 "$chrome" --headless=new --disable-gpu --hide-scrollbars --window-size=430,760 \
    --screenshot="$f.png" "file://$f.html#still" 2>/dev/null
  i=$((i + 1))
done
mkdir -p "$(dirname "$out")"
magick -delay 6 "$work"/f0*.png "$work"/f1[0-5].png -delay 350 "$work/f16.png" \
  -loop 0 -dither None -colors 128 -layers Optimize "$out"
echo "$out"

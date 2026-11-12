# Builds run in a memory-capped scope when systemd is available.
CAP := $(shell command -v systemd-run >/dev/null 2>&1 && echo systemd-run --user --scope -q -p MemoryMax=3G)
BIN := target/release/tattle
DEMO := target/demo-home

.PHONY: build test check demo demo-html example gif shots release clean

build:
	$(CAP) cargo build --release --locked

test:
	$(CAP) cargo test --locked

check:
	cargo fmt --check
	$(CAP) cargo clippy --all-targets --locked -- -D warnings
	$(CAP) cargo test --locked

# Fake home with fake Claude Code and Codex logs, read in colour. For screen
# recordings. Exit code 1 is expected: the demo has critical flags.
demo: build
	clear
	@$(BIN) demo $(DEMO) --color || true

# Same, plus the HTML report (opens in your browser).
demo-html: build
	@$(BIN) demo $(DEMO) --html target/tattle-demo.html >/dev/null 2>&1 || true
	@echo "target/tattle-demo.html  (add #still to the URL to skip the animation)"
	@xdg-open target/tattle-demo.html 2>/dev/null || open target/tattle-demo.html 2>/dev/null || true

# The checked-in example report.
example: build
	@$(BIN) demo $(DEMO) --html examples/tattle-demo.html >/dev/null 2>&1 || true
	@chmod 644 examples/tattle-demo.html

# README GIF of the demo report counting up (needs Chrome and ImageMagick).
gif: build
	sh scripts/demo-gif.sh

# Screenshots of the demo HTML report (needs Chrome or Chromium).
shots: build
	sh scripts/screenshots.sh

# Static x86_64 Linux tarball + SHA256SUMS (musl), in target/dist.
release:
	$(CAP) sh scripts/release.sh

clean:
	cargo clean

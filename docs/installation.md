# Installing Sentinel

**Requires:** macOS 14+, Python 3.12+

---

## Recommended: pipx

[pipx](https://pipx.pypa.io) installs Sentinel into an isolated environment and puts `sentinel` on your PATH. It is the easiest option for end users.

Install pipx if you do not have it:

```bash
brew install pipx
pipx ensurepath
```

Then install Sentinel:

```bash
# CLI + interactive TUI (recommended)
pipx install "sentinel[tui]"

# CLI only (scan, processes, ports, network — no interactive monitor)
pipx install sentinel
```

Verify:

```bash
sentinel doctor
```

---

## pip into a virtual environment

Use this if you want to manage the environment yourself.

```bash
python3 -m venv ~/.venvs/sentinel
source ~/.venvs/sentinel/bin/activate
pip install "sentinel[tui]"
```

Add the venv's `bin/` to your PATH, or call `sentinel` via its full path:

```bash
~/.venvs/sentinel/bin/sentinel doctor
```

---

## Upgrading

**pipx:**

```bash
pipx upgrade sentinel
```

**pip in a venv:**

```bash
source ~/.venvs/sentinel/bin/activate
pip install --upgrade sentinel
```

After upgrading, confirm the new version:

```bash
sentinel version
```

---

## Uninstalling

**pipx:**

```bash
pipx uninstall sentinel
```

**pip in a venv:**

```bash
rm -rf ~/.venvs/sentinel
```

---

## Run automatically on login (launchd)

You can configure Sentinel to run a continuous scan at login using a macOS launchd agent.

### 1. Find your sentinel binary

```bash
which sentinel
```

Note the path — it will be something like `/Users/you/.local/bin/sentinel` (pipx) or `/Users/you/.venvs/sentinel/bin/sentinel` (venv).

### 2. Create the launchd plist

Create `~/Library/LaunchAgents/io.github.eyuelabebe.sentinel.plist`:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>io.github.eyuelabebe.sentinel</string>

  <key>ProgramArguments</key>
  <array>
    <string>/Users/you/.local/bin/sentinel</string>
    <string>scan</string>
    <string>--json</string>
  </array>

  <key>StandardOutPath</key>
  <string>/tmp/sentinel.log</string>

  <key>StandardErrorPath</key>
  <string>/tmp/sentinel-error.log</string>

  <key>StartInterval</key>
  <integer>300</integer>

  <key>RunAtLoad</key>
  <true/>
</dict>
</plist>
```

Replace `/Users/you/.local/bin/sentinel` with the path from step 1.

`StartInterval` is in seconds — `300` runs a scan every 5 minutes.

### 3. Load the agent

```bash
launchctl load ~/Library/LaunchAgents/io.github.eyuelabebe.sentinel.plist
```

To stop it:

```bash
launchctl unload ~/Library/LaunchAgents/io.github.eyuelabebe.sentinel.plist
```

### Notes on launchd mode

- Output goes to `/tmp/sentinel.log`. Rotate or redirect this if you want persistent storage.
- The scan runs as your user — no elevated privileges.
- SIP restrictions apply: some system process details will be partial. Run `sentinel doctor` to see what is visible.
- The interactive TUI (`sentinel` with no arguments) is not suitable for launchd — use `sentinel scan --json` or `sentinel scan` for unattended runs.

---

## Troubleshooting

**`sentinel: command not found` after pipx install**

Run `pipx ensurepath` and open a new terminal. If your shell is zsh, confirm `~/.local/bin` is in your `$PATH`:

```bash
echo $PATH | tr ':' '\n' | grep local
```

**`sentinel doctor` reports partial network access**

This is normal under macOS SIP. Sentinel will show your own processes and connections fully; system processes are partially visible. No action needed.

**TUI does not open (`ModuleNotFoundError: textual`)**

You installed the CLI-only variant. Reinstall with the `tui` extra:

```bash
pipx uninstall sentinel
pipx install "sentinel[tui]"
```

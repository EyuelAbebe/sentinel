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

Sentinel ships a launchd agent that starts the local API server (`sentinel serve`) at login and keeps it running in the background.

### Quick install (recommended)

Requires `sentinel[api]` to be installed first:

```bash
pip install "sentinel[api]"   # or: pipx inject sentinel "sentinel[api]"
bash packaging/install.sh
```

The script:
1. Finds the `sentinel` binary on your PATH
2. Writes a configured plist to `~/Library/LaunchAgents/com.sentinel.agent.plist`
3. Loads the agent via `launchctl`
4. Prints the log path and health URL

Verify it is running:

```bash
curl http://127.0.0.1:7173/health
sentinel doctor   # shows "launchd agent: OK"
```

Logs are written to `~/Library/Logs/sentinel/`.

### Uninstall

```bash
bash packaging/uninstall.sh
```

### Manual plist setup

If you prefer to manage the plist yourself, copy `packaging/com.sentinel.agent.plist`, replace the placeholder tokens (`SENTINEL_BIN`, `SENTINEL_LOG_DIR`, `SENTINEL_USER`) with your actual values, save it to `~/Library/LaunchAgents/com.sentinel.agent.plist`, and load it:

```bash
launchctl load ~/Library/LaunchAgents/com.sentinel.agent.plist
```

### Notes on launchd mode

- The agent runs as your user — no root or elevated privileges required.
- It starts `sentinel serve` (HTTP API on `127.0.0.1:7173`), not the interactive TUI.
- SIP restrictions apply: some system process details are partial. Run `sentinel doctor` to see what is visible.
- Logs rotate automatically when the file exceeds system limits; use `log show` or `Console.app` for structured output.

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

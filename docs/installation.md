# Installing Sentinel

**Requires:** macOS 14+, Python 3.12+

---

## Install from source (recommended for now)

Sentinel is not yet published to PyPI. Clone the repo and install with [Poetry](https://python-poetry.org).

```bash
git clone https://github.com/EyuelAbebe/sentinel.git
cd sentinel
pip install poetry          # if you don't have Poetry yet
poetry install              # installs all runtime + dev dependencies
```

Run it:

```bash
poetry run sentinel doctor  # verify environment
poetry run sentinel scan    # one-shot security scan
poetry run sentinel         # open interactive TUI monitor
poetry run sentinel serve   # start HTTP API + browser dashboard on :7173
```

To avoid typing `poetry run` each time, activate the virtual environment:

```bash
source .venv/bin/activate
sentinel doctor
```

---

## Install from PyPI (once published)

When Sentinel is released to PyPI, you'll be able to install it with [pipx](https://pipx.pypa.io):

```bash
brew install pipx
pipx ensurepath

# CLI + interactive TUI (recommended)
pipx install "sentinel[tui]"

# CLI only (no interactive monitor)
pipx install sentinel
```

Or with pip into a virtual environment:

```bash
python3 -m venv ~/.venvs/sentinel
source ~/.venvs/sentinel/bin/activate
pip install "sentinel[tui]"
```

---

## Upgrading (source install)

```bash
git pull origin main
poetry install
sentinel version
```

---

## Run automatically on login (launchd)

Sentinel ships a launchd agent that starts the local API server (`sentinel serve`) at login.

### Quick install

Requires the `api` extra:

```bash
poetry install --extras api   # or: pip install "sentinel[api]"
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

### Uninstall the agent

```bash
bash packaging/uninstall.sh
```

### Manual plist setup

Copy `packaging/com.sentinel.agent.plist`, replace the placeholder tokens (`SENTINEL_BIN`, `SENTINEL_LOG_DIR`, `SENTINEL_USER`) with your actual values, save it to `~/Library/LaunchAgents/com.sentinel.agent.plist`, and load it:

```bash
launchctl load ~/Library/LaunchAgents/com.sentinel.agent.plist
```

---

## Troubleshooting

**`sentinel: command not found`**

Make sure the Poetry virtualenv is active (`source .venv/bin/activate`) or always prefix with `poetry run`.

**`sentinel doctor` reports partial network access**

Normal under macOS SIP. Sentinel shows your own processes and connections fully; system processes are partially visible. No action needed.

**`ModuleNotFoundError: textual`**

Install the `tui` extra: `poetry install` already includes it for source installs. For pip, reinstall with `pip install "sentinel[tui]"`.

**`ModuleNotFoundError: fastapi` or `uvicorn`**

Install the `api` extra: `poetry install --extras api` or `pip install "sentinel[api]"`.

# TeleRelayV4 (MDMA)

Telegram relay bot for:
- Collecting config links (`vless`, `vmess`, `trojan`, `ss`)
- Testing via Xray + SOCKS
- Grading and reposting to target channel
- Collecting Telegram proxy links and reposting with inline buttons
- Runtime monitoring/config via Streamlit panel

## Project Layout

```text
main.py            # bot runtime (listener + test + post)
panel.py           # Streamlit control panel
tester.py          # config testing pipeline
proxy_tester.py    # Telegram proxy parser/tester
runtime_config.py  # live runtime settings loader
db.py              # SQLite storage layer
config.example.json
requirements.txt
```

## Setup

1) Create virtual environment:

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
```

2) Install dependencies:

```powershell
pip install -r requirements.txt
```

3) Create local config:

```powershell
Copy-Item config.example.json config.json
```

4) Edit `config.json` with real values:
- `telegram.api_id`
- `telegram.api_hash`
- `telegram.bot_token`
- `sources` / `proxy_pipeline.sources`
- `target_channel` / `proxy_pipeline.target_channel`
- `panel.username` / `panel.password`

## Run

Bot:

```powershell
python main.py
```

Panel:

```powershell
streamlit run panel.py
```

## Deploy Notes

- Keep `config.json`, `*.session`, and `*.db` private.
- `.gitignore` is configured to avoid committing runtime secrets/data.
- If you use a server, install Xray and set `xray.binary_path` in `config.json`.
- `curl` must be available on the host.

## Recommended Git Workflow

```powershell
git init
git add .
git commit -m "Initial clean project structure"
```

# TeleRelay

TeleRelay is a lightweight Python tool that relays content from one or more Telegram channels into a target channel, with optional validation and a simple Streamlit panel for visibility.

It is designed to be minimal, configurable through a single JSON file, and suitable for long-running deployments on a VPS.

## Features

- Relay posts from multiple Telegram channels to a single target channel
- Extract and normalize encoded connection/profile links shared in channels
- Deduplication using a local SQLite store
- Optional validation pipeline using local tools
- Optional Streamlit dashboard for monitoring and basic control
- Simple configuration and low resource usage

## Requirements

- Python 3.10+
- Telegram API ID and API Hash (from https://my.telegram.org)
- Optional local binaries for validation (configurable)

## Setup

1. Install dependencies:
```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

2. Create configuration:
```bash
cp config.example.json config.json
```

3. Fill in required fields in `config.json`:
- Telegram credentials
- Source channels
- Target channel

4. Run:
```bash
python main.py
```

On first run, you will be asked to log in to Telegram. A local session file will be created.

## Optional Dashboard

```bash
streamlit run panel.py
```

The dashboard is intended for local or protected environments only.

## Notes

- Do not commit `config.json`, session files, or databases.
- Make sure the Telegram account has access to source channels and permission to post in the target channel.

## License

MIT License

# Atlas Billing Service

A small service that reconciles invoice line items and publishes a daily summary.

## Install

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Run

```bash
python manage.py migrate
python manage.py serve --port 8080
```

## Configuration

Set `DATABASE_URL` and `SUMMARY_BUCKET` in the environment. The service reads
configuration at startup and validates the schema before accepting traffic.

## Operations

The nightly job writes a summary to the object store. To clear a stale cache
during an incident, run `python manage.py cache clear`. The command only
removes files under the service cache directory.

## Testing

```bash
pytest -q
```

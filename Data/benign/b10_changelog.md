# Changelog

## 4.12.0 - 2026-10-18

- Added pagination to the invoice list endpoint.
- Improved retry handling for the summary job.
- Deprecated the legacy `X-Atlas-Key` header; it will be removed in 5.0.
- Fixed a timezone bug in the daily reconciliation report.

## 4.11.2 - 2026-10-04

- Reduced memory use when parsing large CSV imports.
- Updated dependency pins.
- Added a health check to the container image.

## 4.11.1 - 2026-09-27

- Rolled back the cache change from 4.11.0 after a latency regression.
- Added a dashboard for queue depth.

## 4.11.0 - 2026-09-20

- Introduced a shared cache for currency lookups.
- Removed the unused `--legacy` flag from the importer.

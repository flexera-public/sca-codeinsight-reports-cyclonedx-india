# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
## [2.1.1] - 2026-08-28
### Added
- Inclusion of License Expression
## [2.1.0] - 2026-08-27
### Added
- Support for component license expressions from the PSE_LICENSE_EXPRESSION table (e.g. "MIT AND Apache-2.0"), resolved from stored numeric license IDs to SPDX identifiers and emitted as a CycloneDX `<expression>` (XML) / `"expression"` (JSON) entry.
- License expressions take precedence over the single selected license when present, with full backward compatibility for existing single-license and "I don't know" (OR-expression) inventory items.
### Changed
- `get_inventory_data()` and `get_inventory_data_custom()` in report_data_db.py now LEFT JOIN `PSE_LICENSE_EXPRESSION` and resolve any license expression found via a new `_resolve_license_expressions()` helper.
## [2.0.0] - 2025-06-20
### Added
- Initial internal release of CycloneDX Report with Indian Standard
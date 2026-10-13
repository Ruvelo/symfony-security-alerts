# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

## [1.1.0] - 2026-10-13

Backwards compatible: nothing in the 1.0 public API changed, and a 1.0 state store is read as it is. Requires `ruvelo/security-advisories` ^1.1.

### Added

- **Valtry's signed Advisory API is the default source**, with the public feeds (Packagist, OSV, CISA KEV) used automatically whenever Valtry can't answer. By default package names go to Valtry, versions never leave the server, and every answer is signature-checked.
- `security_alerts.source: valtry|public` and `security_alerts.valtry_url`. `RUVELO_ADVISORIES_SOURCE=public` in the environment opts out as well and wins over the config.
- The command's summary and success line ("Checked 67 Composer and 38 npm packages via Valtry, signed"), `--json` (`source`, `sources`) and the profiler panel say which path answered.
- The state store keeps each finding as last seen beside the known keys, so a finding keeps its identity when another source names the same vulnerability differently (CVE and aliases are matched, and the key it was first stored under is kept).
- `VulnerabilityResolvedEvent::$finding`: what the finding was when last seen, when the state has it.

### Changed

- The alert hold-back (an alert that couldn't be sent is announced again next check) now uses the core's `Reconciler::next()` with unacknowledged keys instead of the bundle's own bookkeeping. Behaviour is the same.
- Requires `ruvelo/security-advisories` ^1.1 (was ^1.0).

### Upgrading

Nothing to do. The first check after upgrading recognises everything a 1.0 store knew, whichever source answers, and sends nothing again (covered by tests on both the Valtry and the public path). To keep every request off Valtry, set `source: public`.

## [1.0.0] - 2026-10-12

First release: the Symfony adapter for [`ruvelo/security-advisories`](https://github.com/Ruvelo/security-advisories), mirroring [Laravel Security Alerts](https://github.com/Ruvelo/laravel-security-alerts).

### Added

- `bin/console security-alerts:check` with `--fail-on=exploited|critical|high|medium|any`, `--json`, `--fresh` and `--notify`; exit code 0, 1 (a finding reached `--fail-on`) or 2 (incomplete). A SymfonyStyle table with exploited findings first, and a summary line.
- The core's HTTP client on Symfony HttpClient (PSR-18) and its cache on a Symfony Cache pool (PSR-16).
- Known findings kept in a dedicated filesystem pool under `var/security_alerts` by default, so `cache:clear` doesn't make it re-announce; or any cache pool, or a table through `doctrine/dbal`.
- Alerts through `symfony/notifier` (email and chat channels) or, without it, the Mailer, with a branded email that needs no Twig. An alert that can't be sent is retried on the next check. `notify.min_severity` skips lower new findings; exploited ones are always sent.
- `VulnerabilityFoundEvent`, `VulnerabilityExploitedEvent` and `VulnerabilityResolvedEvent`.
- A daily schedule with `symfony/scheduler`, and `SecurityAlertsSchedule::message()` for your own schedule.
- A Security alerts panel in the Web Profiler (dev).
- The `security_alerts:` config tree: `enabled`, `include_dev`, `project_dir`, `cache_pool`, `cache_ttl`, `http`, `state`, `notify` and `schedule`.

[Unreleased]: https://github.com/Ruvelo/symfony-security-alerts/compare/v1.1.0...HEAD
[1.1.0]: https://github.com/Ruvelo/symfony-security-alerts/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/Ruvelo/symfony-security-alerts/releases/tag/v1.0.0

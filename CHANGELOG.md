# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

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

[Unreleased]: https://github.com/Ruvelo/symfony-security-alerts/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/Ruvelo/symfony-security-alerts/releases/tag/v1.0.0

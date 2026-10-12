# Contributing to Security Alerts Bundle

Thanks for helping! Wrong matches, docs fixes and features are all welcome.

## Before you start

- **A finding that's wrong, or one that's missing:** most likely it belongs in [ruvelo/security-advisories](https://github.com/Ruvelo/security-advisories), which does all the scanning. Open the issue there with the package, the installed version from your lockfile, and the advisory (its `PKSA-`, `GHSA-` or CVE ID). If the advisory itself is wrong, it's best fixed upstream, in the [GitHub Advisory Database](https://github.com/github/advisory-database) or [FriendsOfPHP/security-advisories](https://github.com/FriendsOfPHP/security-advisories).
- **Symfony-specific problems** (the command, config, notifications, state, schedule, profiler): [open an issue](https://github.com/Ruvelo/symfony-security-alerts/issues/new/choose).
- **Features:** open an issue first if it's more than a small change.
- **Security issues:** don't open an issue. See [SECURITY.md](https://github.com/Ruvelo/.github/blob/main/SECURITY.md).

## Setup

You need PHP 8.2+ and Composer. Until `ruvelo/security-advisories` is on Packagist, point Composer at it. Either way, `composer.json` is never changed:

```bash
git clone https://github.com/<you>/symfony-security-alerts && cd symfony-security-alerts
dev/local-composer.sh ~/path/to/security-advisories   # a local checkout...
export COMPOSER=composer.local.json
# ...or, without a checkout: composer config repositories.core vcs https://github.com/Ruvelo/security-advisories
composer install
composer check
```

`composer check` runs exactly what CI runs:

| Command | What it does |
|---|---|
| `composer test` | PHPUnit, with a kernel test app |
| `composer lint` | Code style check (PHP-CS-Fixer, Symfony ruleset) |
| `composer format` | Fix code style |
| `composer analyse` | Static analysis (PHPStan level 8, with phpstan-symfony) |
| `composer demo` | Render the README previews into `build/`; `demo/screenshots.sh` makes `art/` |

CI runs PHP 8.2 to 8.4 on Symfony 6.4 and 7.x, lowest and latest dependencies. To try 6.4 locally, change the `symfony/*` constraints in a copy of `composer.json` to `6.4.*`.

## The tests

`tests/Fixtures` holds real answers from Packagist, OSV and CISA, recorded for the lockfiles of Halyard, a made-up app. `tests/Support/FeedResponder.php` serves them through a `MockHttpClient`; any other URL gets a 404, so a test that reaches the network fails. `BundleTestCase::boot()` starts a kernel with the config you give it.

## Making a change

1. Branch from `main`.
2. Write a test that fails without your change.
3. Keep the public API stable: the command's options and exit codes, config keys, the events, `Checker`, and the services documented in the README. If you must change one, say so in the PR.
4. Keep it quiet: no change should make the bundle send an alert it already sent.
5. Run `composer format` and `composer check`.
6. Add a line under **Unreleased** in [CHANGELOG.md](CHANGELOG.md).

## Style

- `declare(strict_types=1)` everywhere, typed properties and return types.
- No `@phpstan-ignore` or baseline entries: fix the cause.
- Comments explain *why*, not *what*.
- Optional integrations (Notifier, Mailer, Scheduler, Doctrine, the profiler) stay optional: in `suggest`, never loaded unless installed, and in `require-dev` for the tests.

By contributing you agree that your work is released under the [MIT license](LICENSE) and that you'll follow the [code of conduct](https://github.com/Ruvelo/.github/blob/main/CODE_OF_CONDUCT.md).

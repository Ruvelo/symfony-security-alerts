#!/usr/bin/env bash
# Until ruvelo/security-advisories is on Packagist, develop against a local
# checkout without touching composer.json:
#
#   dev/local-composer.sh ~/projects/security-advisories
#   export COMPOSER=composer.local.json
#   composer update && composer check
#
# composer.local.json and composer.local.lock are git-ignored. CI does the same
# thing with a VCS repository: composer config repositories.core vcs <url>
set -euo pipefail
cd "$(dirname "$0")/.."

core=$(realpath "${1:?Usage: dev/local-composer.sh /path/to/security-advisories}")

php -r '
$json = json_decode(file_get_contents("composer.json"), true, 512, JSON_THROW_ON_ERROR);
$json["repositories"] = [["type" => "path", "url" => $argv[1], "options" => ["symlink" => false, "versions" => ["ruvelo/security-advisories" => "1.0.0"]]]];
file_put_contents("composer.local.json", json_encode($json, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE)."\n");
' "$core"

echo "Wrote composer.local.json. Now: export COMPOSER=composer.local.json"

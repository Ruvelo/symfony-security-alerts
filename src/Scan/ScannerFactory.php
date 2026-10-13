<?php

declare(strict_types=1);

namespace Ruvelo\SecurityAlertsBundle\Scan;

use Psr\SimpleCache\CacheInterface;
use Ruvelo\SecurityAdvisories\Cache\ResponseCache;
use Ruvelo\SecurityAdvisories\Cache\Ttls;
use Ruvelo\SecurityAdvisories\Http\JsonClient;
use Ruvelo\SecurityAdvisories\Packages\ComposerLockReader;
use Ruvelo\SecurityAdvisories\Packages\NpmLockReader;
use Ruvelo\SecurityAdvisories\Scanner;
use Ruvelo\SecurityAdvisories\Sources\FallbackAdvisorySource;
use Ruvelo\SecurityAdvisories\Sources\KevCatalogue;
use Ruvelo\SecurityAdvisories\Sources\OsvSource;
use Ruvelo\SecurityAdvisories\Sources\PackagistAdvisorySource;
use Ruvelo\SecurityAdvisories\Valtry\ValtryAdvisorySource;

/**
 * Builds the core's Scanner for the bundle's config. Normally that is
 * Scanner::forProject(): Valtry first, the public feeds when it can't answer,
 * or the public feeds alone when `source` is "public" (or
 * RUVELO_ADVISORIES_SOURCE=public, which wins).
 *
 * @internal
 */
final class ScannerFactory
{
    /**
     * @param array<string, string>|null $valtryKeys The keys Valtry's answers are verified against: null for the ones the core pins. Only tests, which sign their own answers, say otherwise
     */
    public static function create(
        string $projectDir,
        JsonClient $http,
        ?CacheInterface $cache,
        bool $includeDev,
        Ttls $ttls,
        string $source = Scanner::SOURCE_VALTRY,
        string $valtryUrl = ValtryAdvisorySource::URL,
        ?array $valtryKeys = null,
    ): Scanner {
        if ($valtryKeys === null) {
            return Scanner::forProject($projectDir, $http, $cache, $includeDev, $ttls, $source, $valtryUrl);
        }

        $responses = new ResponseCache($cache, $ttls);
        $public = [new PackagistAdvisorySource($http, $responses), new OsvSource($http, $responses)];
        $advisories = Scanner::source($source) === Scanner::SOURCE_PUBLIC
            ? $public
            : [new FallbackAdvisorySource(new ValtryAdvisorySource($http, $responses, $valtryUrl, $valtryKeys), $public)];

        return new Scanner(
            [new ComposerLockReader(rtrim($projectDir, '/\\').'/composer.lock', $includeDev), new NpmLockReader(rtrim($projectDir, '/\\').'/package-lock.json', $includeDev)],
            $advisories,
            new KevCatalogue($http, $responses),
        );
    }
}

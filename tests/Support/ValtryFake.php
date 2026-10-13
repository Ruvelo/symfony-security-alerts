<?php

declare(strict_types=1);

namespace Ruvelo\SecurityAlertsBundle\Tests\Support;

use Ruvelo\SecurityAdvisories\Packages\NpmLockReader;
use Symfony\Component\HttpClient\Response\MockResponse;
use Symfony\Contracts\HttpClient\ResponseInterface;

/**
 * Valtry's Advisory API, faked from the recorded feeds in tests/Fixtures and
 * signed with a keypair made for the test run, which the bundle is told to
 * trust. $tamper breaks the answer in one specific way.
 */
final class ValtryFake
{
    public const URL = 'https://valtry.test/api/advisories/v1/query';

    /** @var non-empty-string|null */
    private static ?string $secret = null;

    private static ?string $public = null;

    /** @var list<string> Ecosystems to report as stale */
    public static array $stale = [];

    /** @var (callable(string): array{0: string, 1: string})|null Gets the signed body, returns [body, signature header] */
    public static $tamper;

    /** @var list<array<mixed>> Decoded request bodies */
    public static array $received = [];

    public static function reset(): void
    {
        self::$stale = [];
        self::$tamper = null;
        self::$received = [];
    }

    /**
     * @return array<string, string> kid => base64 public key
     */
    public static function keys(): array
    {
        if (self::$public === null) {
            $pair = sodium_crypto_sign_keypair();
            self::$secret = sodium_crypto_sign_secretkey($pair);
            self::$public = base64_encode(sodium_crypto_sign_publickey($pair));
        }

        return ['test-1' => self::$public];
    }

    public static function sign(string $body, string $kid = 'test-1'): string
    {
        self::keys();

        return 'ed25519='.base64_encode(sodium_crypto_sign_detached($body, self::$secret ?? throw new \LogicException('No key.'))).'; kid='.$kid;
    }

    /**
     * @param array<string, mixed> $options
     */
    public static function respond(array $options): ResponseInterface
    {
        $raw = $options['body'] ?? '';
        $body = json_decode(\is_string($raw) ? $raw : '', true);
        $body = \is_array($body) ? $body : [];
        self::$received[] = $body;
        $data = self::dataset();

        $advisories = [];
        foreach (\is_array($body['packages'] ?? null) ? $body['packages'] : [] as $p) {
            $key = $p['ecosystem'].':'.$p['name'];
            $advisories[$key] = $data[$key] ?? [];
        }

        $json = (string) json_encode([
            'v' => 1,
            'generated_at' => gmdate('Y-m-d\TH:i:s\Z'),
            'nonce' => $body['nonce'] ?? null,
            'advisories' => (object) $advisories,
            'sources' => [],
            'stale' => self::$stale !== [],
            'stale_sources' => [],
            'stale_ecosystems' => self::$stale,
        ], \JSON_UNESCAPED_SLASHES);
        $header = self::sign($json);

        if (self::$tamper !== null) {
            [$json, $header] = (self::$tamper)($json);
        }

        return new MockResponse($json, ['response_headers' => ['content-type' => 'application/json', 'X-Valtry-Signature' => $header]]);
    }

    /**
     * What Valtry would serve for the fixtures: Packagist records as they
     * are, OSV records with their ranges written as Composer constraints,
     * and the KEV verdict on each.
     *
     * @return array<string, list<array<string, mixed>>>
     */
    public static function dataset(): array
    {
        $dir = __DIR__.'/../Fixtures';
        $kev = [];
        foreach (json_decode((string) file_get_contents($dir.'/kev.json'), true)['vulnerabilities'] as $entry) {
            $kev[strtoupper($entry['cveID'])] = $entry;
        }
        $kevFor = static function (?string $cve) use ($kev): array {
            $entry = $cve !== null ? ($kev[strtoupper($cve)] ?? null) : null;

            return [$entry !== null, $entry === null ? null : [
                'cve' => strtoupper($entry['cveID']),
                'name' => $entry['vulnerabilityName'],
                'date_added' => $entry['dateAdded'],
                'due_date' => $entry['dueDate'] ?? null,
                'ransomware' => strtolower($entry['knownRansomwareCampaignUse'] ?? '') === 'known',
            ]];
        };

        $data = [];
        foreach (json_decode((string) file_get_contents($dir.'/packagist.json'), true)['advisories'] as $name => $list) {
            foreach ($list as $a) {
                [$exploited, $entry] = $kevFor($a['cve'] ?? null);
                $data['composer:'.strtolower($name)][] = [
                    'id' => $a['advisoryId'], 'source' => 'packagist', 'title' => $a['title'], 'link' => $a['link'],
                    'cve' => $a['cve'] ?? null, 'aliases' => [], 'severity' => $a['severity'] ?? null,
                    'affected' => $a['affectedVersions'], 'fixed_in' => [], 'exploited' => $exploited, 'kev' => $entry,
                    'published_at' => str_replace(' ', 'T', (string) $a['reportedAt']).'Z', 'updated_at' => null, 'attribution' => null,
                ];
            }
        }

        // The recorded OSV batch says which advisories apply to which npm package (by position in the lockfile).
        $batch = json_decode((string) file_get_contents($dir.'/osv-querybatch.json'), true)['results'];
        $npm = (new NpmLockReader($dir.'/package-lock.json', false))->packages();
        foreach ($batch as $i => $result) {
            if (!isset($npm[$i])) {
                continue;
            }
            foreach ($result['vulns'] ?? [] as $vuln) {
                $r = json_decode((string) file_get_contents($dir.'/osv/'.$vuln['id'].'.json'), true);
                $cve = null;
                foreach ([$r['id'], ...($r['aliases'] ?? [])] as $alias) {
                    if (preg_match('/^CVE-\d{4}-\d+$/i', $alias) === 1) {
                        $cve = strtoupper($alias);
                        break;
                    }
                }
                [$exploited, $entry] = $kevFor($cve);
                $data['npm:'.strtolower($npm[$i]->name)][] = [
                    'id' => $r['id'], 'source' => 'osv', 'title' => $r['summary'] ?? $r['id'],
                    'link' => 'https://github.com/advisories/'.$r['id'], 'cve' => $cve, 'aliases' => $r['aliases'] ?? [],
                    'severity' => strtolower($r['database_specific']['severity'] ?? ''), 'affected' => '>=0', 'fixed_in' => [],
                    'exploited' => $exploited, 'kev' => $entry, 'published_at' => $r['published'], 'updated_at' => $r['modified'], 'attribution' => null,
                ];
            }
        }

        return $data;
    }
}

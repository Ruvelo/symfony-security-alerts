<?php

declare(strict_types=1);

namespace Ruvelo\SecurityAlertsBundle\Tests\Support;

use Symfony\Component\HttpClient\Response\MockResponse;
use Symfony\Contracts\HttpClient\ResponseInterface;

/**
 * Answers the three feeds from the recorded responses in tests/Fixtures (the
 * lockfiles of Halyard, a made-up app). Nothing reaches the network, and any
 * other URL is a failure.
 */
final class FeedResponder
{
    /** @var list<string> "METHOD url" of every request made */
    public static array $requests = [];

    /** @var array<string, int> URL fragment => status to answer with instead */
    public static array $failing = [];

    public static function reset(): void
    {
        self::$requests = [];
        self::$failing = [];
        ValtryFake::reset();
    }

    /**
     * @param array<string, mixed> $options
     */
    public function __invoke(string $method, string $url, array $options = []): ResponseInterface
    {
        self::$requests[] = $method.' '.$url;

        if ($method === 'POST' && str_contains($url, 'valtry.test')) {
            return isset(self::$failing['valtry.test']) ? new MockResponse('{}', ['http_code' => self::$failing['valtry.test']]) : ValtryFake::respond($options);
        }

        foreach (self::$failing as $fragment => $status) {
            if (str_contains($url, $fragment)) {
                return new MockResponse('{}', ['http_code' => $status]);
            }
        }

        $file = match (true) {
            $method === 'POST' && str_contains($url, 'packagist.org/api/security-advisories') => 'packagist.json',
            $method === 'POST' && str_contains($url, 'api.osv.dev/v1/querybatch') => 'osv-querybatch.json',
            $method === 'GET' && str_contains($url, 'api.osv.dev/v1/vulns/') => 'osv/'.basename(parse_url($url, \PHP_URL_PATH) ?: '').'.json',
            $method === 'GET' && str_contains($url, 'cisa.gov') => 'kev.json',
            default => null,
        };

        $path = $file !== null ? __DIR__.'/../Fixtures/'.$file : null;

        if ($path === null || !is_file($path)) {
            return new MockResponse('{"error":"not recorded"}', ['http_code' => 404]);
        }

        return new MockResponse((string) file_get_contents($path), ['response_headers' => ['content-type' => 'application/json']]);
    }

    public static function count(string $fragment): int
    {
        return \count(array_filter(self::$requests, static fn (string $r): bool => str_contains($r, $fragment)));
    }
}

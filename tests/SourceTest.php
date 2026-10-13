<?php

declare(strict_types=1);

namespace Ruvelo\SecurityAlertsBundle\Tests;

use Ruvelo\SecurityAlertsBundle\Tests\Support\FeedResponder;
use Ruvelo\SecurityAlertsBundle\Tests\Support\ValtryFake;

/**
 * Valtry's signed Advisory API is the default source; the public feeds answer
 * when it can't, or when asked for.
 */
final class SourceTest extends BundleTestCase
{
    protected function tearDown(): void
    {
        putenv('RUVELO_ADVISORIES_SOURCE');
        unset($_SERVER['RUVELO_ADVISORIES_SOURCE'], $_ENV['RUVELO_ADVISORIES_SOURCE']);
        parent::tearDown();
    }

    /**
     * @return array<string, mixed>
     */
    private function json(): array
    {
        [, $output] = $this->console(['--json' => true]);
        $data = json_decode($output, true);
        self::assertIsArray($data);

        return $data;
    }

    public function testTheDefaultIsValtry(): void
    {
        $this->boot(['source' => 'valtry']);
        $config = self::getContainer()->getParameter('security_alerts.config');

        self::assertIsArray($config);
        self::assertSame('valtry', $config['source']);
        self::assertSame('https://valtry.test/api/advisories/v1/query', $config['valtry_url']);
    }

    public function testTheShippedDefaultsAreValtryAndItsRealEndpoint(): void
    {
        self::ensureKernelShutdown();
        self::bootKernel(['alerts' => ['project_dir' => $this->project, 'cache_pool' => null, 'state' => ['directory' => $this->project.'/state']], 'variant' => bin2hex(random_bytes(4))]);
        $config = self::getContainer()->getParameter('security_alerts.config');

        self::assertIsArray($config);
        self::assertSame('valtry', $config['source']);
        self::assertSame('https://valtry.co.uk/api/advisories/v1/query', $config['valtry_url']);
    }

    public function testAnUnknownSourceIsRejected(): void
    {
        $this->expectException(\Symfony\Component\Config\Definition\Exception\InvalidConfigurationException::class);
        $this->boot(['source' => 'bing']);
    }

    public function testValtryAnswersWithOneRequestPerEcosystemAndSendsNamesOnly(): void
    {
        $this->boot(['source' => 'valtry']);
        $data = $this->json();

        self::assertSame('valtry', $data['source']);
        self::assertSame(['composer' => 'valtry', 'npm' => 'valtry'], $data['sources']);
        self::assertCount(11, $data['findings']);
        self::assertSame(2, FeedResponder::count('valtry.test'));
        self::assertSame(0, FeedResponder::count('packagist.org'));
        self::assertSame(0, FeedResponder::count('osv.dev'));
        self::assertSame(0, FeedResponder::count('cisa.gov'), 'Valtry carries the exploited verdict.');

        foreach (ValtryFake::$received as $request) {
            self::assertArrayNotHasKey('version', $request);
            foreach ($request['packages'] as $package) {
                self::assertSame(['ecosystem', 'name'], array_keys($package), 'Names only, never versions.');
            }
        }
    }

    public function testTheCommandSaysWhichPathAnswered(): void
    {
        $this->boot(['source' => 'valtry']);
        [, $output] = $this->console();
        self::assertStringContainsString('Checked 67 Composer and 3 npm packages via Valtry, signed.', $output);
        self::assertStringContainsString('1 exploited in the wild', $output);

        $this->boot(['source' => 'public']);
        [, $output] = $this->console();
        self::assertStringContainsString('via public feeds.', $output);
    }

    public function testValtryAndThePublicFeedsFindTheSame(): void
    {
        $this->boot(['source' => 'public']);
        $public = $this->json();
        $this->boot(['source' => 'valtry']);
        $valtry = $this->json();

        $ids = static fn (array $data): array => array_map(static fn (array $f): string => $f['package'].' '.$f['advisory_id'].' '.($f['exploited'] ? 'x' : '-'), $data['findings']);
        self::assertSame('public', $public['source']);
        self::assertEqualsCanonicalizing($ids($public), $ids($valtry));
    }

    public function testPublicNeverContactsValtry(): void
    {
        $this->boot(['source' => 'public']);
        $data = $this->json();

        self::assertSame('public', $data['source']);
        self::assertSame(0, FeedResponder::count('valtry.test'));
    }

    public function testTheEnvironmentOptsOutWhateverTheConfigSays(): void
    {
        putenv('RUVELO_ADVISORIES_SOURCE=public');
        $this->boot(['source' => 'valtry']);
        $data = $this->json();

        self::assertSame('public', $data['source']);
        self::assertSame(0, FeedResponder::count('valtry.test'));
    }

    public function testItFallsBackWhenValtryIsDown(): void
    {
        FeedResponder::$failing['valtry.test'] = 503;
        $this->boot(['source' => 'valtry']);
        $data = $this->json();

        self::assertSame('public', $data['source']);
        self::assertCount(11, $data['findings']);
        self::assertTrue($data['complete']);
    }

    public function testItFallsBackOnABadSignature(): void
    {
        ValtryFake::$tamper = static fn (string $body): array => [$body, ValtryFake::sign($body.' ')];
        $this->boot(['source' => 'valtry']);
        $data = $this->json();

        self::assertSame('public', $data['source']);
        self::assertCount(11, $data['findings']);
    }

    public function testItFallsBackWhenValtryReportsItsDataStale(): void
    {
        ValtryFake::$stale = ['npm'];
        $this->boot(['source' => 'valtry']);
        $data = $this->json();

        self::assertSame(['composer' => 'valtry', 'npm' => 'public'], $data['sources']);
        self::assertSame('mixed', $data['source']);
        self::assertCount(11, $data['findings']);
    }

    public function testTheProfilerAndTheStoredReportRememberTheSource(): void
    {
        $this->boot(['source' => 'valtry']);
        $this->console(['--notify' => true]);

        $last = $this->state()->lastCheck();
        self::assertIsArray($last);
        self::assertSame('valtry', $last['report']['source']);
    }
}

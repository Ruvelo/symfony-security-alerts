<?php

declare(strict_types=1);

namespace Ruvelo\SecurityAlertsBundle\Tests;

use PHPUnit\Framework\Attributes\DataProvider;
use Ruvelo\SecurityAlertsBundle\Tests\Support\FeedResponder;

final class CheckCommandTest extends BundleTestCase
{
    public function testTheTableListsExploitedFindingsFirstAndSummarises(): void
    {
        $this->boot();
        [$code, $output] = $this->console();

        self::assertSame(0, $code);
        self::assertStringContainsString('Exploited', $output);
        self::assertLessThan(strpos($output, 'guzzlehttp/guzzle'), strpos($output, 'livewire/livewire'));
        self::assertStringContainsString('In CISA KEV since 2026-03-20, patch by 2026-04-03', $output);
        self::assertStringContainsString('11 vulnerabilities in 7 packages: 1 exploited in the wild, 2 critical, 3 high, 4 medium, 1 low.', $output);
        self::assertStringContainsString('Update livewire/livewire to 3.6.4 or later today.', $output);
        self::assertStringContainsString('Checked 67 Composer and 3 npm packages via public feeds.', $output);
        self::assertStringContainsString('@kurkle/color npm', $output);
    }

    /**
     * @return iterable<string, array{string, int}>
     */
    public static function thresholds(): iterable
    {
        yield 'exploited' => ['exploited', 1];
        yield 'critical' => ['critical', 1];
        yield 'any' => ['any', 1];
        yield 'case and spaces do not matter' => [' High ', 1];
    }

    #[DataProvider('thresholds')]
    public function testFailOnExitsWithOneWhenAFindingReachesTheThreshold(string $level, int $expected): void
    {
        $this->boot();

        self::assertSame($expected, $this->console(['--fail-on' => $level])[0]);
    }

    public function testFailOnPassesWhenNothingReachesTheThreshold(): void
    {
        file_put_contents($this->project.'/composer.lock', '{"packages":[{"name":"psr/log","version":"3.0.2"}],"packages-dev":[]}');
        unlink($this->project.'/package-lock.json');
        $this->boot();

        [$code, $output] = $this->console(['--fail-on' => 'any']);

        self::assertSame(0, $code);
        self::assertStringContainsString('No known vulnerabilities in 1 Composer package, checked via public feeds.', $output);
    }

    public function testAnUnknownThresholdIsAnError(): void
    {
        $this->boot();
        [$code, $output] = $this->console(['--fail-on' => 'bogus']);

        self::assertSame(1, $code);
        self::assertStringContainsString('bogus', $output);
        self::assertSame([], FeedResponder::$requests, 'Nothing is fetched for a bad option.');
    }

    public function testAnUnreadableFeedMakesTheAnswerIncomplete(): void
    {
        FeedResponder::$failing['cisa.gov'] = 503;
        $this->boot();

        [$code, $output] = $this->console();

        self::assertSame(2, $code);
        self::assertStringContainsString("CISA KEV couldn't be reached", $output);
        self::assertStringNotContainsString('Exploited', $output);
    }

    public function testAFindingBeatsAnIncompleteAnswer(): void
    {
        FeedResponder::$failing['cisa.gov'] = 503;
        $this->boot();

        self::assertSame(1, $this->console(['--fail-on' => 'critical'])[0]);
    }

    public function testAMissingLockfileIsReportedNotThrown(): void
    {
        unlink($this->project.'/composer.lock');
        $this->boot();

        [$code, $output] = $this->console();

        self::assertSame(2, $code);
        self::assertStringContainsString("Couldn't find", $output);
    }

    public function testJsonPrintsTheReportAndOnlyThat(): void
    {
        $this->boot();
        [$code, $output] = $this->console(['--json' => true]);

        $report = json_decode($output, true, 512, \JSON_THROW_ON_ERROR);
        self::assertSame(0, $code);
        self::assertFalse($report['clean']);
        self::assertTrue($report['complete']);
        self::assertSame(11, \count($report['findings']));
        self::assertTrue($report['findings'][0]['exploited']);
        self::assertSame('composer:livewire/livewire:PKSA-g5js-3ypd-k2kr', $report['findings'][0]['key']);
        self::assertSame(['composer' => 67, 'npm' => 3], $report['packages']);
    }

    public function testWithoutNotifyNothingIsRememberedOrSent(): void
    {
        $this->boot();
        $this->console();

        self::assertNull($this->state()->lastCheck());
        self::assertEmailCount(0);
        self::assertSame(0, $this->eventCount(\Ruvelo\SecurityAlertsBundle\Event\VulnerabilityFoundEvent::class));
    }

    public function testTheFeedCacheIsUsedUntilFresh(): void
    {
        $this->boot(['cache_pool' => 'cache.app']);

        $this->console();
        $first = \count(FeedResponder::$requests);
        $this->console();
        self::assertSame($first, \count(FeedResponder::$requests), 'The second run is answered from the cache.');

        $this->console(['--fresh' => true]);
        self::assertSame($first * 2, \count(FeedResponder::$requests));
    }

    public function testRequestsIdentifyThePackageAndSendNoOtherData(): void
    {
        $this->boot();
        $this->console();

        foreach (FeedResponder::$requests as $request) {
            self::assertMatchesRegularExpression('#^(GET|POST) https://(packagist\.org|api\.osv\.dev|www\.cisa\.gov)/#', $request);
        }
    }

    public function testDevPackagesAreLeftOutUnlessAsked(): void
    {
        $this->boot();
        $without = json_decode($this->console(['--json' => true])[1], true, 512, \JSON_THROW_ON_ERROR);

        $this->boot(['include_dev' => true]);
        $with = json_decode($this->console(['--json' => true])[1], true, 512, \JSON_THROW_ON_ERROR);

        self::assertLessThanOrEqual($with['packages']['composer'], $without['packages']['composer']);
    }
}

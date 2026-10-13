<?php

declare(strict_types=1);

namespace Ruvelo\SecurityAlertsBundle\Tests;

use PHPUnit\Framework\Attributes\DataProvider;
use Ruvelo\SecurityAdvisories\Finding;
use Ruvelo\SecurityAlertsBundle\Check\Checker;
use Ruvelo\SecurityAlertsBundle\Event\VulnerabilityExploitedEvent;
use Ruvelo\SecurityAlertsBundle\Event\VulnerabilityFoundEvent;
use Ruvelo\SecurityAlertsBundle\Event\VulnerabilityResolvedEvent;

/**
 * An app that ran 1.0 has a state store holding the keys it already
 * announced, and a last check without the 1.1 "seen" data. The first 1.1
 * check must recognise them, whichever source answers, and send nothing.
 */
final class UpgradeFromOneZeroTest extends BundleTestCase
{
    /**
     * The state as 1.0 left it after its checks: finding key => exploited, and a last check with the report and no "seen".
     *
     * @return array<string, bool>
     */
    private function seedOneZeroState(): array
    {
        $this->boot(['source' => 'public']);
        $checker = self::getContainer()->get('security_alerts.checker');
        \assert($checker instanceof Checker);
        $report = $checker->scan(true);

        $known = [];
        foreach ($report->findings as $finding) {
            $known[$finding->key()] = $finding->isExploited();
        }
        self::assertCount(11, $known);

        $oneZeroReport = $report->toArray();
        unset($oneZeroReport['source'], $oneZeroReport['sources'], $oneZeroReport['unchecked'], $oneZeroReport['notes'], $oneZeroReport['v']);
        $this->state()->remember($known, ['report' => $oneZeroReport, 'announced' => 11, 'delivery' => 'sent']);
        self::assertArrayNotHasKey('seen', $this->state()->lastCheck() ?? []);
        $this->events = [];

        return $known;
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function sources(): iterable
    {
        yield 'public feeds' => ['public'];
        yield 'Valtry' => ['valtry'];
    }

    #[DataProvider('sources')]
    public function testOneZeroStateIsKnownWhicheverSourceAnswers(string $source): void
    {
        $known = $this->seedOneZeroState();

        $this->boot(['source' => $source]);
        [$code, $output] = $this->console(['--notify' => true]);

        self::assertSame(0, $code);
        self::assertStringNotContainsString('Sent an alert', $output);
        self::assertEmailCount(0);
        self::assertSame(0, $this->eventCount(VulnerabilityFoundEvent::class));
        self::assertSame(0, $this->eventCount(VulnerabilityExploitedEvent::class));
        self::assertSame(0, $this->eventCount(VulnerabilityResolvedEvent::class));
        self::assertSame($known, $this->state()->known(), 'The stored identities are untouched.');

        $last = $this->state()->lastCheck();
        self::assertIsArray($last);
        self::assertSame($source, $last['report']['source']);
        self::assertCount(11, $last['seen'], 'From now on each stored key remembers its finding.');

        // And the next check is quiet too.
        [, $output] = $this->console(['--notify' => true]);
        self::assertStringNotContainsString('Sent an alert', $output);
        self::assertEmailCount(0);
    }

    public function testAnUpdatedPackageStillResolvesAfterTheUpgrade(): void
    {
        $this->seedOneZeroState();
        $this->install('livewire/livewire', '3.6.4');

        $this->boot(['source' => 'valtry']);
        $this->console(['--notify' => true]);

        self::assertSame(0, $this->eventCount(VulnerabilityFoundEvent::class));
        self::assertGreaterThan(0, $this->eventCount(VulnerabilityResolvedEvent::class));
        self::assertEmailCount(0);
        foreach ($this->events[VulnerabilityResolvedEvent::class] as $event) {
            self::assertInstanceOf(VulnerabilityResolvedEvent::class, $event);
            self::assertSame('livewire/livewire', $event->package());
            self::assertNull($event->finding, 'A 1.0 state has the key only.');
        }
    }

    public function testAVulnerabilityStoredUnderAnotherIdIsRecognisedByItsCve(): void
    {
        $this->boot(['source' => 'public']);
        $this->console(['--notify' => true]);

        // The store knows one vulnerability under an id no source uses any more, and remembers what it was.
        $known = $this->state()->known();
        $last = $this->state()->lastCheck();
        self::assertIsArray($last);
        $original = 'composer:livewire/livewire:PKSA-g5js-3ypd-k2kr';
        self::assertArrayHasKey($original, $known);
        $old = $last['seen'][$original];
        $old['advisory_id'] = 'OLD-ID';
        $old['aliases'] = [];
        $oldFinding = Finding::fromArray($old);
        self::assertNotNull($oldFinding);
        $oldKey = $oldFinding->key();
        self::assertSame('composer:livewire/livewire:OLD-ID', $oldKey);

        $renamed = [];
        foreach ($known as $key => $exploited) {
            $renamed[$key === $original ? $oldKey : $key] = $exploited;
        }
        $seen = [];
        foreach ($last['seen'] as $key => $finding) {
            $seen[$key === $original ? $oldKey : $key] = $key === $original ? $old : $finding;
        }
        $this->state()->remember($renamed, ['seen' => $seen] + $last);
        $this->events = [];

        $this->boot(['source' => 'valtry']);
        [, $output] = $this->console(['--notify' => true]);

        self::assertStringNotContainsString('Sent an alert', $output);
        self::assertEmailCount(0);
        self::assertSame(0, $this->eventCount(VulnerabilityFoundEvent::class));
        self::assertSame(0, $this->eventCount(VulnerabilityResolvedEvent::class));
        self::assertArrayHasKey($oldKey, $this->state()->known(), 'The key it was first stored under is kept.');
        self::assertArrayNotHasKey($original, $this->state()->known());
    }
}

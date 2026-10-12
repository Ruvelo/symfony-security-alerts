<?php

declare(strict_types=1);

namespace Ruvelo\SecurityAlertsBundle\Tests;

use Doctrine\DBAL\Connection;
use Psr\Cache\CacheItemPoolInterface;
use Ruvelo\SecurityAdvisories\Ecosystem;
use Ruvelo\SecurityAdvisories\Finding;
use Ruvelo\SecurityAlertsBundle\Event\VulnerabilityExploitedEvent;
use Ruvelo\SecurityAlertsBundle\Event\VulnerabilityFoundEvent;
use Ruvelo\SecurityAlertsBundle\Event\VulnerabilityResolvedEvent;
use Ruvelo\SecurityAlertsBundle\Notification\Alert;
use Ruvelo\SecurityAlertsBundle\Notification\AlertRenderer;
use Ruvelo\SecurityAlertsBundle\Tests\Support\FeedResponder;
use Symfony\Component\Mime\Email;

/**
 * State and reconcile across runs, with the plain Mailer (no Notifier).
 */
final class NotifyTest extends BundleTestCase
{
    private function clear(string $pool): void
    {
        $cache = self::getContainer()->get($pool);
        \assert($cache instanceof CacheItemPoolInterface);
        $cache->clear();
    }

    private function dbal(): Connection
    {
        $connection = self::getContainer()->get('test.dbal');
        \assert($connection instanceof Connection);

        return $connection;
    }

    private function mail(int $index = 0): Email
    {
        $message = self::getMailerMessage($index);
        self::assertInstanceOf(Email::class, $message);

        return $message;
    }

    public function testTheFirstCheckAnnouncesEverythingOnceAndTheSecondIsQuiet(): void
    {
        $this->boot();

        [$code, $output] = $this->console(['--notify' => true]);
        self::assertSame(0, $code);
        self::assertStringContainsString('Sent an alert about 11 findings.', $output);
        self::assertEmailCount(1);
        self::assertSame(11, $this->eventCount(VulnerabilityFoundEvent::class));
        self::assertSame(1, $this->eventCount(VulnerabilityExploitedEvent::class));

        $email = $this->mail();
        self::assertSame('Halyard: exploited vulnerability in livewire/livewire, patch today', $email->getSubject());
        self::assertSame('ops@example.com', $email->getTo()[0]->getAddress());
        self::assertSame('alerts@example.com', $email->getFrom()[0]->getAddress());
        self::assertStringContainsString("In CISA's catalogue since 20 March 2026; US agencies must patch by 3 April 2026", (string) $email->getHtmlBody());
        self::assertStringContainsString('Update to 3.6.4 or later', (string) $email->getHtmlBody());
        self::assertStringContainsString('EXPLOITED IN THE WILD', (string) $email->getTextBody());

        [, $output] = $this->console(['--notify' => true]);
        self::assertStringNotContainsString('Sent an alert', $output);
        self::assertEmailCount(1);
        self::assertSame(11, $this->eventCount(VulnerabilityFoundEvent::class), 'Events fire once per finding.');
    }

    public function testAFindingThatBecomesExploitedIsAnnouncedAgainAndNeverDowngraded(): void
    {
        FeedResponder::$failing['cisa.gov'] = 503;
        $this->boot();

        [$code] = $this->console(['--notify' => true]);
        self::assertSame(2, $code);
        self::assertSame('Halyard: 11 new vulnerabilities in your dependencies', $this->mail()->getSubject());
        self::assertSame(0, $this->eventCount(VulnerabilityExploitedEvent::class));

        FeedResponder::$failing = [];
        $this->console(['--notify' => true]);
        self::assertEmailCount(2);
        self::assertSame('Halyard: exploited vulnerability in livewire/livewire, patch today', $this->mail(1)->getSubject());
        self::assertSame(1, $this->eventCount(VulnerabilityExploitedEvent::class));
        self::assertSame(11, $this->eventCount(VulnerabilityFoundEvent::class), 'The exploited one was not new.');

        FeedResponder::$failing['cisa.gov'] = 503;
        $this->console(['--notify' => true]);
        self::assertEmailCount(2); // An unreachable CISA feed neither lowers the alarm nor re-sends it.
        self::assertSame(1, $this->eventCount(VulnerabilityExploitedEvent::class));
    }

    public function testUpdatingAPackageResolvesItsFindings(): void
    {
        $this->boot();
        $this->console(['--notify' => true]);

        $this->install('livewire/livewire', '3.9.0');
        $this->console(['--notify' => true]);

        self::assertSame(2, $this->eventCount(VulnerabilityResolvedEvent::class));
        $keys = [];
        foreach ($this->events[VulnerabilityResolvedEvent::class] as $event) {
            self::assertInstanceOf(VulnerabilityResolvedEvent::class, $event);
            $keys[] = $event->key;
        }
        self::assertContains('composer:livewire/livewire:PKSA-g5js-3ypd-k2kr', $keys);
        self::assertSame('livewire/livewire', (new VulnerabilityResolvedEvent($keys[0]))->package());
        self::assertEmailCount(1); // Resolved findings are events, not emails.
    }

    public function testAFailingFeedNeverResolvesAnything(): void
    {
        $this->boot();
        $this->console(['--notify' => true]);

        $this->install('livewire/livewire', '3.9.0');
        FeedResponder::$failing['packagist.org'] = 500;
        [$code] = $this->console(['--notify' => true]);

        self::assertSame(2, $code);
        self::assertSame(0, $this->eventCount(VulnerabilityResolvedEvent::class));
    }

    public function testACacheClearDoesNotReannounceWithTheDefaultStore(): void
    {
        $this->boot(['cache_pool' => 'cache.app']);
        $this->console(['--notify' => true]);

        $this->clear('cache.app');
        $this->clear('cache.system');
        $this->console(['--notify' => true]);

        self::assertEmailCount(1);
        self::assertFileExists($this->project.'/state');
    }

    public function testAnAppPoolStoreForgetsWhenThatPoolIsCleared(): void
    {
        $this->boot(['cache_pool' => null, 'state' => ['store' => 'pool', 'pool' => 'cache.app']]);
        $this->console(['--notify' => true]);
        $this->clear('cache.app');
        $this->console(['--notify' => true]);

        self::assertEmailCount(2);
    }

    public function testThePoolStoreRequiresAPool(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->boot(['state' => ['store' => 'pool']]);
    }

    public function testTheDoctrineStoreRemembersInATable(): void
    {
        $this->boot(['state' => ['store' => 'doctrine', 'connection' => 'test.dbal', 'table' => 'alerts_state']]);
        $this->console(['--notify' => true]);
        $this->console(['--notify' => true]);

        self::assertEmailCount(1);
        $rows = $this->dbal()->fetchFirstColumn('SELECT name FROM alerts_state ORDER BY name');
        self::assertSame(['known', 'last_check'], $rows);
    }

    public function testAnAlertThatCannotBeSentIsRetriedAndItsEventsWait(): void
    {
        $state = ['directory' => $this->project.'/state'];
        $this->boot(['state' => $state], ['mailer' => ['dsn' => 'smtp://127.0.0.1:1']]);

        [$code, $output] = $this->console(['--notify' => true]);
        self::assertSame(2, $code);
        self::assertStringContainsString("Couldn't send the alert", $output);
        self::assertSame(0, $this->eventCount(VulnerabilityFoundEvent::class));

        $this->boot(['state' => $state]);
        [$code] = $this->console(['--notify' => true]);
        self::assertSame(0, $code);
        self::assertEmailCount(1);
        self::assertSame(11, $this->eventCount(VulnerabilityFoundEvent::class));
        self::assertSame(1, $this->eventCount(VulnerabilityExploitedEvent::class));
    }

    public function testMinSeverityHoldsBackLowerNewFindingsButNotTheEvents(): void
    {
        $this->boot(['notify' => ['recipients' => ['ops@example.com'], 'from' => 'a@example.com', 'min_severity' => 'critical']]);
        $this->console(['--notify' => true]);

        $text = (string) $this->mail()->getTextBody();
        self::assertStringContainsString('predis/predis', $text);
        self::assertStringContainsString('livewire/livewire', $text);
        self::assertStringNotContainsString('maatwebsite/excel', $text);
        self::assertSame(11, $this->eventCount(VulnerabilityFoundEvent::class));
    }

    public function testExploitedFindingsIgnoreMinSeverity(): void
    {
        file_put_contents($this->project.'/package-lock.json', '{"lockfileVersion":3,"packages":{}}');
        $this->boot(['notify' => ['recipients' => ['ops@example.com'], 'from' => 'a@example.com', 'min_severity' => 'critical']]);
        $this->install('livewire/livewire', '3.6.2');
        $this->console(['--notify' => true]);

        self::assertStringContainsString('exploited vulnerability in livewire/livewire', (string) $this->mail()->getSubject());
    }

    public function testWithNobodyToTellItSaysSoAndStillRecords(): void
    {
        $this->boot(['notify' => ['recipients' => []]]);

        [$code, $output] = $this->console(['--notify' => true]);

        self::assertSame(0, $code);
        self::assertStringContainsString('nobody was told', $output);
        self::assertEmailCount(0);
        self::assertSame(11, $this->eventCount(VulnerabilityFoundEvent::class));
    }

    public function testAdvisoryTextCannotInjectMarkupIntoTheEmail(): void
    {
        $finding = new Finding(Ecosystem::Composer, 'a/b', '1.0.0', 'X-1', '<script>alert(1)</script>', link: 'javascript:alert(1)');
        $html = AlertRenderer::html(new Alert('App', [$finding]));

        self::assertStringNotContainsString('<script>', $html);
        self::assertStringNotContainsString('javascript:', $html);
        self::assertStringContainsString('&lt;script&gt;', $html);
    }
}

<?php

declare(strict_types=1);

namespace Ruvelo\SecurityAlertsBundle\Tests;

use Ruvelo\SecurityAlertsBundle\Profiler\SecurityAlertsDataCollector;
use Symfony\Bundle\TwigBundle\TwigBundle;
use Symfony\Bundle\WebProfilerBundle\WebProfilerBundle;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Twig\Environment;

final class ProfilerTest extends BundleTestCase
{
    /**
     * @return array<string, mixed>
     */
    private function profiler(): array
    {
        return ['profiler' => ['enabled' => true, 'collect' => false], 'router' => ['resource' => 'kernel::loadRoutes', 'utf8' => true]];
    }

    private function collector(): SecurityAlertsDataCollector
    {
        $collector = self::getContainer()->get('security_alerts.profiler');
        self::assertInstanceOf(SecurityAlertsDataCollector::class, $collector);
        $collector->collect(new Request(), new Response());

        return $collector;
    }

    public function testThePanelIsNotRegisteredWithoutTheWebProfiler(): void
    {
        $this->boot();

        self::assertFalse(self::getContainer()->has('security_alerts.profiler'));
    }

    public function testThePanelShowsTheLatestStoredReportWithoutCallingAFeed(): void
    {
        $this->boot([], $this->profiler(), [TwigBundle::class, WebProfilerBundle::class]);

        $empty = $this->collector();
        self::assertFalse($empty->hasReport());

        $this->console(['--notify' => true]);
        $requests = \count(Support\FeedResponder::$requests);

        $collector = $this->collector();
        self::assertSame($requests, \count(Support\FeedResponder::$requests), 'The profiler reads the stored report.');
        self::assertTrue($collector->hasReport());
        self::assertSame(11, $collector->getTotal());
        self::assertSame(1, $collector->getExploitedCount());
        self::assertTrue($collector->isComplete());
        self::assertNotNull($collector->getCheckedAt());
        self::assertSame('security_alerts', $collector->getName());
    }

    public function testTheTemplateRendersTheFindings(): void
    {
        $this->boot([], $this->profiler(), [TwigBundle::class, WebProfilerBundle::class]);
        $this->console(['--notify' => true]);

        $twig = self::getContainer()->get('twig');
        self::assertInstanceOf(Environment::class, $twig);
        $template = $twig->load('@SecurityAlerts/data_collector/security_alerts.html.twig');
        $html = $template->renderBlock('panel', ['collector' => $this->collector()]);

        self::assertStringContainsString('livewire/livewire', $html);
        self::assertStringContainsString('Exploited', $html);
        self::assertStringContainsString('CVE-2025-54068', $html);

        $empty = $template->renderBlock('panel', ['collector' => new SecurityAlertsDataCollector(new \Ruvelo\SecurityAlertsBundle\State\CachePoolStateStore(new \Symfony\Component\Cache\Adapter\ArrayAdapter()))]);
        self::assertStringContainsString('No check has been recorded yet', $empty);
    }
}

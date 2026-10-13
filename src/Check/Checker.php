<?php

declare(strict_types=1);

namespace Ruvelo\SecurityAlertsBundle\Check;

use Psr\Log\LoggerInterface;
use Ruvelo\SecurityAdvisories\Finding;
use Ruvelo\SecurityAdvisories\Reconciler;
use Ruvelo\SecurityAdvisories\Report;
use Ruvelo\SecurityAdvisories\Scanner;
use Ruvelo\SecurityAlertsBundle\Event\VulnerabilityExploitedEvent;
use Ruvelo\SecurityAlertsBundle\Event\VulnerabilityFoundEvent;
use Ruvelo\SecurityAlertsBundle\Event\VulnerabilityResolvedEvent;
use Ruvelo\SecurityAlertsBundle\Notification\Alert;
use Ruvelo\SecurityAlertsBundle\Notification\NotifySettings;
use Ruvelo\SecurityAlertsBundle\Notification\Sender;
use Ruvelo\SecurityAlertsBundle\State\StateStore;
use Symfony\Contracts\EventDispatcher\EventDispatcherInterface;

/**
 * scan() only looks. check() also remembers, tells people about what is new
 * and fires the events: each finding is announced once.
 */
final class Checker
{
    public function __construct(
        private readonly Scanner $scanner,
        private readonly Reconciler $reconciler,
        private readonly StateStore $state,
        private readonly Sender $sender,
        private readonly EventDispatcherInterface $events,
        private readonly NotifySettings $settings,
        private readonly ?LoggerInterface $logger = null,
    ) {
    }

    public function scan(bool $fresh = false): Report
    {
        return $this->scanner->scan($fresh);
    }

    public function check(bool $fresh = false): CheckResult
    {
        $report = $this->scanner->scan($fresh);
        $known = $this->state->known();
        $seen = $this->seen();
        $changes = $this->reconciler->reconcile($known, $report, $seen);

        /** @var array<string, Finding> $announce */
        $announce = [];
        foreach ($changes->new as $finding) {
            if ($this->settings->wants($finding)) {
                $announce[$finding->key()] = $finding;
            }
        }
        foreach ($changes->exploited as $finding) {
            $announce[$finding->key()] = $finding;
        }
        $announce = array_values($announce);

        $delivery = Delivery::None;
        $error = null;
        $held = [];

        if ($announce !== []) {
            try {
                $delivery = $this->sender->send(new Alert($this->settings->appName(), $announce)) ? Delivery::Sent : Delivery::NotConfigured;
            } catch (\Throwable $e) {
                $delivery = Delivery::Failed;
                $error = $e->getMessage();
                $this->logger?->warning('Security alert could not be sent: '.$e->getMessage(), ['exception' => $e]);

                // Not recorded, so the next check announces them again.
                foreach ($announce as $finding) {
                    $held[$finding->key()] = true;
                }
            }
        }

        $next = $this->reconciler->next($known, $report, array_keys($held), $seen);

        $this->state->remember($next, [
            'report' => $report->toArray(),
            'announced' => $delivery === Delivery::Sent ? \count($announce) : 0,
            'delivery' => $delivery->value,
            // Each stored key's finding as last seen: how a vulnerability is recognised when another source names it differently.
            'seen' => $this->reconciler->lastSeen($seen, $report, $next),
        ]);

        foreach ($changes->new as $finding) {
            if (!isset($held[$finding->key()])) {
                $this->events->dispatch(new VulnerabilityFoundEvent($finding));
            }
        }
        foreach ($changes->exploited as $finding) {
            if (!isset($held[$finding->key()])) {
                $this->events->dispatch(new VulnerabilityExploitedEvent($finding));
            }
        }
        foreach ($changes->resolved as $key) {
            $this->events->dispatch(new VulnerabilityResolvedEvent($key, $changes->resolvedFinding($key)));
        }

        return new CheckResult($report, $changes, $delivery, $announce, \count($held), $error);
    }

    /**
     * What the last check stored beside the known keys (a check from before
     * 1.1 stored none, and keys alone still work).
     *
     * @return array<string, array<mixed>>
     */
    private function seen(): array
    {
        $seen = $this->state->lastCheck()['seen'] ?? [];
        $out = [];

        foreach (\is_array($seen) ? $seen : [] as $key => $finding) {
            if (\is_string($key) && \is_array($finding)) {
                $out[$key] = $finding;
            }
        }

        return $out;
    }
}

<?php

declare(strict_types=1);

namespace Ruvelo\SecurityAlertsBundle\Profiler;

use Ruvelo\SecurityAlertsBundle\State\StateStore;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\DataCollector\DataCollector;

/**
 * Shows the latest stored report in the profiler. It never calls a feed: it
 * only reads what the last `security-alerts:check --notify` recorded.
 */
final class SecurityAlertsDataCollector extends DataCollector
{
    public function __construct(private readonly StateStore $state)
    {
    }

    public function collect(Request $request, Response $response, ?\Throwable $exception = null): void
    {
        $last = $this->state->lastCheck();
        $report = \is_array($last['report'] ?? null) ? $last['report'] : null;

        $this->data = [
            'has_report' => $report !== null,
            'report' => $report,
            'delivery' => \is_array($last) && \is_string($last['delivery'] ?? null) ? $last['delivery'] : null,
        ];
    }

    public function getName(): string
    {
        return 'security_alerts';
    }

    public function reset(): void
    {
        $this->data = [];
    }

    public function hasReport(): bool
    {
        return ($this->data['has_report'] ?? false) === true;
    }

    /**
     * @return array<string, mixed>
     */
    public function getReport(): array
    {
        return \is_array($this->data['report'] ?? null) ? $this->data['report'] : [];
    }

    /**
     * @return list<array<string, mixed>>
     */
    public function getFindings(): array
    {
        $findings = $this->getReport()['findings'] ?? [];

        return \is_array($findings) ? array_values($findings) : [];
    }

    public function getExploitedCount(): int
    {
        return \count(array_filter($this->getFindings(), static fn (array $f): bool => ($f['exploited'] ?? false) === true));
    }

    public function getTotal(): int
    {
        return \count($this->getFindings());
    }

    public function isComplete(): bool
    {
        return ($this->getReport()['complete'] ?? true) === true;
    }

    public function getCheckedAt(): ?string
    {
        $at = $this->getReport()['checked_at'] ?? null;

        return \is_string($at) ? $at : null;
    }
}

<?php

declare(strict_types=1);

namespace Ruvelo\SecurityAlertsBundle\Notification;

use Ruvelo\SecurityAdvisories\Finding;
use Ruvelo\SecurityAdvisories\Severity;

final readonly class NotifySettings
{
    /**
     * @param list<string> $recipients
     * @param list<string> $channels
     */
    public function __construct(
        public array $recipients = [],
        public array $channels = ['email'],
        public ?string $from = null,
        private ?string $appName = null,
        public ?string $minSeverity = null,
        private string $projectDir = '',
    ) {
    }

    public function appName(): string
    {
        if ($this->appName !== null && $this->appName !== '') {
            return $this->appName;
        }

        $name = basename(rtrim($this->projectDir, '/\\'));

        return $name !== '' ? $name : 'Your app';
    }

    /**
     * New findings below min_severity aren't announced; exploited ones always are.
     */
    public function wants(Finding $finding): bool
    {
        return $finding->isExploited() || $this->minSeverity === null || $finding->severity->atLeast(Severity::parse($this->minSeverity));
    }
}

<?php

declare(strict_types=1);

namespace Ruvelo\SecurityAlertsBundle\Notification;

use Ruvelo\SecurityAdvisories\Finding;

/**
 * What one alert says: the exploited findings first, then the other new ones.
 */
final readonly class Alert
{
    /** @var list<Finding> */
    public array $exploited;

    /** @var list<Finding> */
    public array $others;

    /**
     * @param list<Finding> $findings
     */
    public function __construct(public string $appName, array $findings)
    {
        $this->exploited = array_values(array_filter($findings, static fn (Finding $f): bool => $f->isExploited()));
        $this->others = array_values(array_filter($findings, static fn (Finding $f): bool => !$f->isExploited()));
    }

    public function count(): int
    {
        return \count($this->exploited) + \count($this->others);
    }

    public function isUrgent(): bool
    {
        return $this->exploited !== [];
    }

    public function subject(): string
    {
        if ($this->exploited !== []) {
            return $this->appName.': '.(\count($this->exploited) === 1
                ? 'exploited vulnerability in '.$this->exploited[0]->package.', patch today'
                : \count($this->exploited).' exploited vulnerabilities, patch today');
        }

        return $this->appName.': '.($this->count() === 1
            ? 'new vulnerability in '.$this->others[0]->package
            : $this->count().' new vulnerabilities in your dependencies');
    }

    public function heading(): string
    {
        $exploited = \count($this->exploited);
        if ($exploited > 0) {
            return ($exploited === 1 ? 'A vulnerability' : $exploited.' vulnerabilities').' in '.$this->appName.' '.($exploited === 1 ? 'is' : 'are').' being exploited';
        }

        return ($this->count() === 1 ? 'A new vulnerability' : $this->count().' new vulnerabilities').' in '.$this->appName;
    }

    public function intro(): string
    {
        $exploited = \count($this->exploited);
        $others = \count($this->others);

        $text = $exploited > 0
            ? 'Attackers are using '.($exploited === 1 ? 'this flaw' : 'these flaws').' in the wild, according to CISA\'s catalogue of known exploited vulnerabilities. Update today.'
            : 'A package '.$this->appName.' has installed has a published security advisory.';

        if ($exploited > 0 && $others > 0) {
            $text .= ' '.($others === 1 ? 'One other new advisory' : $others.' other new advisories').' below.';
        }

        return $text;
    }

    public function footer(): string
    {
        return 'You\'ll hear about each of these once. Run bin/console security-alerts:check to see every open alert.';
    }

    public static function fix(Finding $finding): string
    {
        if ($finding->fixedIn === null) {
            return 'no fixed version listed yet';
        }

        return str_starts_with($finding->fixedIn, '>') ? 'fixed after '.substr($finding->fixedIn, 1) : 'update to '.$finding->fixedIn.' or later';
    }
}

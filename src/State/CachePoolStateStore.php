<?php

declare(strict_types=1);

namespace Ruvelo\SecurityAlertsBundle\State;

use Psr\Cache\CacheItemPoolInterface;

/**
 * Keeps the state in a PSR-6 pool. Only as durable as the pool: the default is
 * a dedicated filesystem pool that cache:clear doesn't touch.
 */
final class CachePoolStateStore implements StateStore
{
    public function __construct(private readonly CacheItemPoolInterface $pool)
    {
    }

    public function known(): array
    {
        $value = $this->pool->getItem('known')->get();
        $known = [];

        foreach (\is_array($value) ? $value : [] as $key => $exploited) {
            $known[(string) $key] = $exploited === true;
        }

        return $known;
    }

    public function lastCheck(): ?array
    {
        $value = $this->pool->getItem('last_check')->get();

        return \is_array($value) ? $value : null;
    }

    public function remember(array $known, array $lastCheck): void
    {
        $this->pool->save($this->pool->getItem('known')->set($known));
        $this->pool->save($this->pool->getItem('last_check')->set($lastCheck));
    }
}

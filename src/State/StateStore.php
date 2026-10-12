<?php

declare(strict_types=1);

namespace Ruvelo\SecurityAlertsBundle\State;

/**
 * Remembers what the last check knew, so the next one only announces what is new.
 */
interface StateStore
{
    /**
     * @return array<string, bool> Finding key => whether it was exploited when last seen
     */
    public function known(): array;

    /**
     * @return array<string, mixed>|null What remember() was given as the last check, or null before the first one
     */
    public function lastCheck(): ?array;

    /**
     * @param array<string, bool>  $known
     * @param array<string, mixed> $lastCheck JSON-friendly
     */
    public function remember(array $known, array $lastCheck): void;
}

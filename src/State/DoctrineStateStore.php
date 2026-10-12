<?php

declare(strict_types=1);

namespace Ruvelo\SecurityAlertsBundle\State;

use Doctrine\DBAL\Connection;

/**
 * Keeps the state in one small key/value table, created on first use. Plain
 * DBAL, so it works with or without the ORM.
 *
 * Tell Doctrine to leave the table alone, or a migration diff will want to
 * drop it: schema_filter: '~^(?!security_alerts_state$)~'
 */
final class DoctrineStateStore implements StateStore
{
    private bool $ready = false;

    public function __construct(private readonly Connection $connection, private readonly string $table = 'security_alerts_state')
    {
    }

    public function known(): array
    {
        $value = $this->read('known');
        $known = [];

        foreach ($value ?? [] as $key => $exploited) {
            $known[(string) $key] = $exploited === true;
        }

        return $known;
    }

    public function lastCheck(): ?array
    {
        return $this->read('last_check');
    }

    public function remember(array $known, array $lastCheck): void
    {
        $this->ensureTable();

        $this->connection->transactional(function () use ($known, $lastCheck): void {
            $this->write('known', $known);
            $this->write('last_check', $lastCheck);
        });
    }

    /**
     * @return array<string, mixed>|null
     */
    private function read(string $name): ?array
    {
        $this->ensureTable();

        $json = $this->connection->fetchOne("SELECT payload FROM {$this->table} WHERE name = ?", [$name]);
        $value = \is_string($json) ? json_decode($json, true) : null;

        return \is_array($value) ? $value : null;
    }

    /**
     * @param array<string, mixed> $value
     */
    private function write(string $name, array $value): void
    {
        $this->connection->executeStatement("DELETE FROM {$this->table} WHERE name = ?", [$name]);
        $this->connection->executeStatement("INSERT INTO {$this->table} (name, payload) VALUES (?, ?)", [$name, json_encode($value, \JSON_THROW_ON_ERROR | \JSON_UNESCAPED_SLASHES)]);
    }

    private function ensureTable(): void
    {
        if ($this->ready) {
            return;
        }

        try {
            $this->connection->fetchOne("SELECT 1 FROM {$this->table} WHERE name = ?", ['known']);
        } catch (\Throwable) {
            $this->connection->executeStatement("CREATE TABLE IF NOT EXISTS {$this->table} (name VARCHAR(64) NOT NULL PRIMARY KEY, payload TEXT NOT NULL)");
        }

        $this->ready = true;
    }
}

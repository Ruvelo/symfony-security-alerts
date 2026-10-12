<?php

declare(strict_types=1);

namespace Ruvelo\SecurityAlertsBundle\Tests;

use Doctrine\DBAL\DriverManager;
use PHPUnit\Framework\TestCase;
use Ruvelo\SecurityAlertsBundle\State\CachePoolStateStore;
use Ruvelo\SecurityAlertsBundle\State\DoctrineStateStore;
use Ruvelo\SecurityAlertsBundle\State\StateStore;
use Symfony\Component\Cache\Adapter\ArrayAdapter;

final class StateStoreTest extends TestCase
{
    /**
     * @return iterable<string, array{StateStore}>
     */
    public static function stores(): iterable
    {
        yield 'cache pool' => [new CachePoolStateStore(new ArrayAdapter())];
        yield 'doctrine' => [new DoctrineStateStore(DriverManager::getConnection(['driver' => 'pdo_sqlite', 'memory' => true]))];
    }

    #[\PHPUnit\Framework\Attributes\DataProvider('stores')]
    public function testItStartsEmptyAndRemembersWhatItWasGiven(StateStore $store): void
    {
        self::assertSame([], $store->known());
        self::assertNull($store->lastCheck());

        $store->remember(['composer:a/b:X-1' => false, 'npm:c:Y-2' => true], ['delivery' => 'sent']);
        $store->remember(['composer:a/b:X-1' => true], ['delivery' => 'none']);

        self::assertSame(['composer:a/b:X-1' => true], $store->known());
        self::assertSame(['delivery' => 'none'], $store->lastCheck());
    }

    public function testTheDoctrineTableNameIsKeptForTheSchemaFilterAdvice(): void
    {
        $connection = DriverManager::getConnection(['driver' => 'pdo_sqlite', 'memory' => true]);
        (new DoctrineStateStore($connection, 'my_alerts'))->remember([], []);

        self::assertSame(['my_alerts'], $connection->createSchemaManager()->listTableNames());
    }
}

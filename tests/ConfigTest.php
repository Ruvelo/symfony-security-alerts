<?php

declare(strict_types=1);

namespace Ruvelo\SecurityAlertsBundle\Tests;

use Ruvelo\SecurityAlertsBundle\Notification\MailerSender;
use Ruvelo\SecurityAlertsBundle\State\CachePoolStateStore;
use Ruvelo\SecurityAlertsBundle\State\DoctrineStateStore;
use Symfony\Component\Config\Definition\Exception\InvalidConfigurationException;

final class ConfigTest extends BundleTestCase
{
    /**
     * @return array<string, mixed>
     */
    private function config(): array
    {
        $this->boot();
        $config = self::getContainer()->getParameter('security_alerts.config');
        \assert(\is_array($config));

        return $config;
    }

    public function testDefaults(): void
    {
        $this->boot(['project_dir' => '%kernel.project_dir%', 'notify' => []]);
        $config = self::getContainer()->getParameter('security_alerts.config');

        self::assertIsArray($config);
        self::assertTrue($config['enabled']);
        self::assertFalse($config['include_dev']);
        self::assertSame('cache.app', $config['cache_pool'] ?? 'cache.app');
        self::assertSame(['recipients' => [], 'channels' => ['email'], 'from' => null, 'app_name' => null, 'min_severity' => null], $config['notify']);
        self::assertSame(['enabled' => true, 'time' => '07:00', 'timezone' => null, 'name' => 'security_alerts'], $config['schedule']);
        self::assertSame('filesystem', $config['state']['store']);
        self::assertSame(['advisories' => 3600, 'kev' => 21600, 'osv_details' => 604800], $config['cache_ttl']);
        self::assertEquals(15.0, $config['http']['timeout']);
    }

    public function testTheDefaultStateLivesOutsideTheKernelCache(): void
    {
        $this->boot(['state' => ['directory' => '%kernel.project_dir%/var/security_alerts']]);

        $store = self::getContainer()->get('security_alerts.state');
        self::assertInstanceOf(CachePoolStateStore::class, $store);
        $config = self::getContainer()->getParameter('security_alerts.config');
        self::assertIsArray($config);
        self::assertStringNotContainsString((string) self::$kernel?->getCacheDir(), $config['state']['directory']);
    }

    public function testTheMailerIsTheFallback(): void
    {
        $this->boot();

        self::assertInstanceOf(MailerSender::class, self::getContainer()->get('security_alerts.sender'));
    }

    public function testRecipientsAndChannelsAcceptCommaSeparatedStrings(): void
    {
        $this->boot(['notify' => ['recipients' => 'a@example.com, b@example.com ,', 'channels' => 'chat']]);
        $config = self::getContainer()->getParameter('security_alerts.config');

        self::assertIsArray($config);
        self::assertSame(['a@example.com', 'b@example.com'], $config['notify']['recipients']);
        self::assertSame(['chat'], $config['notify']['channels']);
    }

    public function testTheCommandIsRegistered(): void
    {
        $this->boot();

        $command = (new \Symfony\Bundle\FrameworkBundle\Console\Application(self::$kernel ?? throw new \LogicException()))->find('security-alerts:check');
        self::assertSame('security-alerts:check', $command->getName());
        self::assertContains('fail-on', array_keys($command->getDefinition()->getOptions()));
    }

    public function testDisabledRegistersNothing(): void
    {
        $this->boot(['enabled' => false]);

        self::assertFalse(self::getContainer()->has('security_alerts.checker'));
        $this->expectException(\Symfony\Component\Console\Exception\CommandNotFoundException::class);
        (new \Symfony\Bundle\FrameworkBundle\Console\Application(self::$kernel ?? throw new \LogicException()))->find('security-alerts:check');
    }

    /**
     * @return iterable<string, array{array<string, mixed>}>
     */
    public static function invalid(): iterable
    {
        yield 'severity' => [['notify' => ['min_severity' => 'severe']]];
        yield 'time' => [['schedule' => ['time' => '7am']]];
        yield 'hour' => [['schedule' => ['time' => '25:00']]];
        yield 'store' => [['state' => ['store' => 'redis']]];
        yield 'table' => [['state' => ['table' => 'a; DROP TABLE x']]];
        yield 'ttl' => [['cache_ttl' => ['kev' => -1]]];
        yield 'timeout' => [['http' => ['timeout' => 0]]];
    }

    /**
     * @param array<string, mixed> $config
     */
    #[\PHPUnit\Framework\Attributes\DataProvider('invalid')]
    public function testInvalidValuesAreRejected(array $config): void
    {
        $this->expectException(InvalidConfigurationException::class);
        $this->boot($config);
    }

    public function testAnUnreachableProjectDirectoryIsAProblemNotACrash(): void
    {
        $this->boot(['project_dir' => $this->project.'/nowhere']);

        [$code, $output] = $this->console();

        self::assertSame(2, $code);
        self::assertStringContainsString("Couldn't find", $output);
    }

    public function testTheDoctrineStoreIsWiredWhenAsked(): void
    {
        $this->boot(['state' => ['store' => 'doctrine', 'connection' => 'test.dbal']]);

        self::assertInstanceOf(DoctrineStateStore::class, self::getContainer()->get('security_alerts.state'));
        self::assertNotSame([], $this->config());
    }
}

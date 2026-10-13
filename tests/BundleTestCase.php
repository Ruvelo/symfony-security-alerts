<?php

declare(strict_types=1);

namespace Ruvelo\SecurityAlertsBundle\Tests;

use Ruvelo\SecurityAlertsBundle\Event\VulnerabilityExploitedEvent;
use Ruvelo\SecurityAlertsBundle\Event\VulnerabilityFoundEvent;
use Ruvelo\SecurityAlertsBundle\Event\VulnerabilityResolvedEvent;
use Ruvelo\SecurityAlertsBundle\State\StateStore;
use Ruvelo\SecurityAlertsBundle\Tests\Support\FeedResponder;
use Ruvelo\SecurityAlertsBundle\Tests\Support\TestKernel;
use Ruvelo\SecurityAlertsBundle\Tests\Support\ValtryFake;
use Symfony\Bundle\FrameworkBundle\Console\Application;
use Symfony\Bundle\FrameworkBundle\Test\KernelTestCase;
use Symfony\Bundle\FrameworkBundle\Test\MailerAssertionsTrait;
use Symfony\Bundle\FrameworkBundle\Test\NotificationAssertionsTrait;
use Symfony\Component\Console\Tester\ApplicationTester;
use Symfony\Component\EventDispatcher\EventDispatcher;
use Symfony\Component\Filesystem\Filesystem;
use Symfony\Component\HttpKernel\KernelInterface;

abstract class BundleTestCase extends KernelTestCase
{
    use MailerAssertionsTrait;
    use NotificationAssertionsTrait;

    protected string $project;

    /** @var array<class-string, list<object>> */
    protected array $events = [];

    protected function setUp(): void
    {
        FeedResponder::reset();
        $this->events = [];
        $this->project = sys_get_temp_dir().'/security-alerts-bundle-'.bin2hex(random_bytes(6));
        (new Filesystem())->mkdir($this->project);
        $this->useFixtureLockfiles();
    }

    protected function tearDown(): void
    {
        if (static::$kernel instanceof TestKernel) {
            static::$kernel->cleanup();
        }
        parent::tearDown();
        (new Filesystem())->remove($this->project);
    }

    /**
     * @param array<string, mixed> $options
     */
    protected static function createKernel(array $options = []): KernelInterface
    {
        return new TestKernel($options['alerts'] ?? [], $options['framework'] ?? [], $options['bundles'] ?? [], $options['variant'] ?? 'default');
    }

    /**
     * Boots an app. Defaults suit most tests: the fixture project, no feed cache,
     * state beside the project, and a mailer that records instead of sending.
     *
     * @param array<string, mixed>                                                     $alerts
     * @param array<string, mixed>                                                     $framework
     * @param list<class-string<\Symfony\Component\HttpKernel\Bundle\BundleInterface>> $bundles
     */
    protected function boot(array $alerts = [], array $framework = [], array $bundles = []): void
    {
        self::ensureKernelShutdown();

        // The recorded fixtures are the public feeds' answers; the Valtry path has its own tests.
        $alerts += ['source' => 'public', 'valtry_url' => ValtryFake::URL, 'project_dir' => $this->project, 'cache_pool' => null, 'notify' => ['recipients' => ['ops@example.com'], 'from' => 'alerts@example.com', 'app_name' => 'Halyard']];
        $alerts['state'] = ($alerts['state'] ?? []) + ['directory' => $this->project.'/state'];
        $framework += ['mailer' => ['dsn' => 'null://null']];

        self::bootKernel(['alerts' => $alerts, 'framework' => $framework, 'bundles' => $bundles, 'variant' => bin2hex(random_bytes(4))]);

        $dispatcher = self::getContainer()->get('event_dispatcher');
        \assert($dispatcher instanceof EventDispatcher);
        foreach ([VulnerabilityFoundEvent::class, VulnerabilityExploitedEvent::class, VulnerabilityResolvedEvent::class] as $event) {
            $dispatcher->addListener($event, function (object $e): void {
                $this->events[$e::class][] = $e;
            });
        }
    }

    /**
     * @param array<string, mixed> $input
     *
     * @return array{int, string}
     */
    protected function console(array $input = []): array
    {
        $application = new Application(self::$kernel ?? throw new \LogicException('Boot first.'));
        $application->setAutoExit(false);
        $tester = new ApplicationTester($application);
        $code = $tester->run(['command' => 'security-alerts:check'] + $input, ['decorated' => false, 'interactive' => false]);

        return [$code, $tester->getDisplay()];
    }

    protected function state(): StateStore
    {
        $state = self::getContainer()->get('security_alerts.state');
        \assert($state instanceof StateStore);

        return $state;
    }

    protected function eventCount(string $class): int
    {
        return \count($this->events[$class] ?? []);
    }

    protected function useFixtureLockfiles(): void
    {
        copy(__DIR__.'/Fixtures/composer.lock', $this->project.'/composer.lock');
        copy(__DIR__.'/Fixtures/package-lock.json', $this->project.'/package-lock.json');
    }

    /**
     * Pretends an installed package is at another version.
     */
    protected function install(string $package, string $version): void
    {
        $lock = json_decode((string) file_get_contents($this->project.'/composer.lock'), true, 512, \JSON_THROW_ON_ERROR);
        foreach (['packages', 'packages-dev'] as $section) {
            foreach ($lock[$section] ?? [] as $i => $entry) {
                if ($entry['name'] === $package) {
                    $lock[$section][$i]['version'] = $version;
                }
            }
        }
        file_put_contents($this->project.'/composer.lock', json_encode($lock, \JSON_THROW_ON_ERROR));
    }
}

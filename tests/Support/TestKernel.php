<?php

declare(strict_types=1);

namespace Ruvelo\SecurityAlertsBundle\Tests\Support;

use Doctrine\DBAL\Connection;
use Doctrine\DBAL\DriverManager;
use Ruvelo\SecurityAlertsBundle\SecurityAlertsBundle;
use Symfony\Bundle\FrameworkBundle\FrameworkBundle;
use Symfony\Bundle\FrameworkBundle\Kernel\MicroKernelTrait;
use Symfony\Component\DependencyInjection\Compiler\CompilerPassInterface;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;

use function Symfony\Component\DependencyInjection\Loader\Configurator\service;

use Symfony\Component\Filesystem\Filesystem;
use Symfony\Component\HttpClient\MockHttpClient;
use Symfony\Component\HttpKernel\Kernel;

/**
 * A tiny app: the framework, this bundle, and a mock HTTP client that serves
 * the recorded feeds. Each test describes the config it wants.
 */
final class TestKernel extends Kernel
{
    use MicroKernelTrait;

    /**
     * @param array<string, mixed>                                                     $alerts       The security_alerts config
     * @param array<string, mixed>                                                     $framework    Extra framework config (mailer, notifier...)
     * @param list<class-string<\Symfony\Component\HttpKernel\Bundle\BundleInterface>> $extraBundles
     */
    public function __construct(
        private readonly array $alerts = [],
        private readonly array $framework = [],
        private readonly array $extraBundles = [],
        private readonly string $variant = 'default',
        bool $debug = true,
    ) {
        parent::__construct('test', $debug);
    }

    public function registerBundles(): iterable
    {
        yield new FrameworkBundle();
        yield new SecurityAlertsBundle();

        foreach ($this->extraBundles as $bundle) {
            yield new $bundle();
        }
    }

    public function getProjectDir(): string
    {
        return \dirname(__DIR__);
    }

    public function getCacheDir(): string
    {
        return $this->varDir().'/cache';
    }

    public function getLogDir(): string
    {
        return $this->varDir().'/log';
    }

    public function cleanup(): void
    {
        (new Filesystem())->remove($this->varDir());
    }

    private function varDir(): string
    {
        return \dirname(__DIR__, 2).'/var/tests/'.substr(sha1(serialize([$this->alerts, $this->framework, $this->extraBundles, $this->variant])), 0, 12);
    }

    protected function build(ContainerBuilder $container): void
    {
        // The bundle verifies Valtry's answers against the keys the core pins; tests sign their own.
        $container->addCompilerPass(new class implements CompilerPassInterface {
            public function process(ContainerBuilder $container): void
            {
                if ($container->hasDefinition('security_alerts.scanner')) {
                    $container->getDefinition('security_alerts.scanner')->replaceArgument(7, ValtryFake::keys());
                }
            }
        });
    }

    protected function configureContainer(ContainerConfigurator $container): void
    {
        $container->extension('framework', $this->framework + [
            'secret' => 'test',
            'test' => true,
            'http_client' => ['enabled' => true],
            'handle_all_throwables' => true,
            'php_errors' => ['log' => true],
        ]);

        $container->extension('security_alerts', $this->alerts + ['http' => ['client' => 'test.http_client']]);

        $services = $container->services();
        $services->set('test.http_client', MockHttpClient::class)->args([service(FeedResponder::class)]);
        $services->set(FeedResponder::class);

        if (class_exists(DriverManager::class)) {
            $services->set('test.dbal', Connection::class)
                ->factory([DriverManager::class, 'getConnection'])
                ->args([['driver' => 'pdo_sqlite', 'memory' => true]]);
        }
    }
}

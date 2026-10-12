<?php

declare(strict_types=1);

namespace Ruvelo\SecurityAlertsBundle\DependencyInjection;

use Ruvelo\SecurityAdvisories\Cache\Ttls;
use Ruvelo\SecurityAdvisories\Reconciler;
use Ruvelo\SecurityAdvisories\Scanner;
use Ruvelo\SecurityAlertsBundle\Check\Checker;
use Ruvelo\SecurityAlertsBundle\Command\CheckCommand;
use Ruvelo\SecurityAlertsBundle\Http\JsonClientFactory;
use Ruvelo\SecurityAlertsBundle\Notification\NotifySettings;
use Ruvelo\SecurityAlertsBundle\Profiler\SecurityAlertsDataCollector;
use Ruvelo\SecurityAlertsBundle\Schedule\CheckMessageHandler;
use Ruvelo\SecurityAlertsBundle\Schedule\SecurityAlertsSchedule;
use Ruvelo\SecurityAlertsBundle\State\CachePoolStateStore;
use Ruvelo\SecurityAlertsBundle\State\DoctrineStateStore;
use Symfony\Component\Cache\Adapter\FilesystemAdapter;
use Symfony\Component\Cache\Psr16Cache;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;
use Symfony\Component\DependencyInjection\Reference;
use Symfony\Component\Scheduler\ScheduleProviderInterface;

/**
 * Registers the services for a processed `security_alerts` config.
 *
 * @internal
 */
final class Wiring
{
    /**
     * @param array<string, mixed> $config
     */
    public function load(array $config, ContainerConfigurator $configurator, ContainerBuilder $container): void
    {
        $container->setParameter('security_alerts.config', $config);

        if ($config['enabled'] !== true) {
            return;
        }

        $http = $config['http'];
        $ttl = $config['cache_ttl'];
        $notify = $config['notify'];
        $state = $config['state'];

        $container->register('security_alerts.http', \Ruvelo\SecurityAdvisories\Http\JsonClient::class)
            ->setFactory([JsonClientFactory::class, 'create'])
            ->setArguments([$http['client'] !== null ? new Reference($http['client'], ContainerBuilder::NULL_ON_INVALID_REFERENCE) : null, $http['timeout'], $http['tries']]);

        $container->register('security_alerts.ttls', Ttls::class)
            ->setArguments([$ttl['advisories'], $ttl['kev'], $ttl['osv_details']]);

        $cache = null;
        if ($config['cache_pool'] !== null) {
            $container->register('security_alerts.cache', Psr16Cache::class)
                ->setArguments([new Reference($config['cache_pool'])]);
            $cache = new Reference('security_alerts.cache');
        }

        $container->register('security_alerts.scanner', Scanner::class)
            ->setFactory([Scanner::class, 'forProject'])
            ->setArguments([$config['project_dir'], new Reference('security_alerts.http'), $cache, $config['include_dev'], new Reference('security_alerts.ttls')]);

        $container->register('security_alerts.reconciler', Reconciler::class);

        $container->register('security_alerts.notify_settings', NotifySettings::class)
            ->setArguments([$notify['recipients'], $notify['channels'], $notify['from'], $notify['app_name'], $notify['min_severity'], $config['project_dir']]);

        $this->state($container, $state);

        $container->register('security_alerts.checker', Checker::class)
            ->setPublic(true)
            ->setArguments([
                new Reference('security_alerts.scanner'),
                new Reference('security_alerts.reconciler'),
                new Reference('security_alerts.state'),
                new Reference('security_alerts.sender'),
                new Reference('event_dispatcher'),
                new Reference('security_alerts.notify_settings'),
                new Reference('logger', ContainerBuilder::NULL_ON_INVALID_REFERENCE),
            ]);
        $container->setAlias(Checker::class, 'security_alerts.checker');

        $container->register('security_alerts.command.check', CheckCommand::class)
            ->setArguments([new Reference('security_alerts.checker')])
            ->addTag('console.command');

        $this->schedule($container, $config['schedule']);
        $this->profiler($container);
    }

    /**
     * @param array<string, mixed> $state
     */
    private function state(ContainerBuilder $container, array $state): void
    {
        switch ($state['store']) {
            case 'doctrine':
                $container->register('security_alerts.state', DoctrineStateStore::class)
                    ->setArguments([new Reference($state['connection']), $state['table']]);
                break;
            case 'pool':
                if (!\is_string($state['pool']) || $state['pool'] === '') {
                    throw new \InvalidArgumentException('security_alerts.state.pool must name a cache pool when state.store is "pool".');
                }
                $container->register('security_alerts.state', CachePoolStateStore::class)
                    ->setArguments([new Reference($state['pool'])]);
                break;
            default:
                // Outside var/cache, so cache:clear and deploys that wipe it leave the known findings alone.
                $container->register('security_alerts.state.pool', FilesystemAdapter::class)
                    ->setArguments(['security_alerts', 0, $state['directory']]);
                $container->register('security_alerts.state', CachePoolStateStore::class)
                    ->setArguments([new Reference('security_alerts.state.pool')]);
        }
    }

    /**
     * @param array<string, mixed> $schedule
     */
    private function schedule(ContainerBuilder $container, array $schedule): void
    {
        if ($schedule['enabled'] !== true || !interface_exists(ScheduleProviderInterface::class) || !interface_exists(\Symfony\Component\Messenger\MessageBusInterface::class)) {
            return;
        }

        $container->register('security_alerts.schedule', SecurityAlertsSchedule::class)
            ->setArguments([$schedule['time'], $schedule['timezone']])
            ->addTag('scheduler.schedule_provider', ['name' => $schedule['name']]);

        $container->register('security_alerts.schedule.handler', CheckMessageHandler::class)
            ->setArguments([new Reference('security_alerts.checker')])
            ->addTag('messenger.message_handler');
    }

    private function profiler(ContainerBuilder $container): void
    {
        $bundles = $container->hasParameter('kernel.bundles') ? $container->getParameter('kernel.bundles') : [];
        $debug = $container->hasParameter('kernel.debug') && $container->getParameter('kernel.debug') === true;

        if (!$debug || !\is_array($bundles) || !isset($bundles['WebProfilerBundle'])) {
            return;
        }

        $container->register('security_alerts.profiler', SecurityAlertsDataCollector::class)
            ->setArguments([new Reference('security_alerts.state')])
            ->addTag('data_collector', ['template' => '@SecurityAlerts/data_collector/security_alerts.html.twig', 'id' => 'security_alerts', 'priority' => 200]);
    }
}

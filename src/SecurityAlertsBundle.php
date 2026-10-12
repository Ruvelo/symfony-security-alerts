<?php

declare(strict_types=1);

namespace Ruvelo\SecurityAlertsBundle;

use Ruvelo\SecurityAlertsBundle\DependencyInjection\Compiler\SenderPass;
use Ruvelo\SecurityAlertsBundle\DependencyInjection\Configuration;
use Symfony\Component\Config\Definition\Configurator\DefinitionConfigurator;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;
use Symfony\Component\HttpKernel\Bundle\AbstractBundle;

/**
 * Tells you when a package your app runs becomes vulnerable, and when a known
 * flaw starts being exploited in the wild. The scanning is done by
 * ruvelo/security-advisories; this bundle wires it into Symfony.
 */
final class SecurityAlertsBundle extends AbstractBundle
{
    protected string $extensionAlias = 'security_alerts';

    public function configure(DefinitionConfigurator $definition): void
    {
        Configuration::define($definition);
    }

    public function build(ContainerBuilder $container): void
    {
        $container->addCompilerPass(new SenderPass());
    }

    /**
     * @param array<string, mixed> $config
     */
    public function loadExtension(array $config, ContainerConfigurator $container, ContainerBuilder $builder): void
    {
        (new DependencyInjection\Wiring())->load($config, $container, $builder);
    }
}

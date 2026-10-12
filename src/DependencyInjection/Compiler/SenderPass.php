<?php

declare(strict_types=1);

namespace Ruvelo\SecurityAlertsBundle\DependencyInjection\Compiler;

use Ruvelo\SecurityAlertsBundle\Notification\MailerSender;
use Ruvelo\SecurityAlertsBundle\Notification\NotifierSender;
use Ruvelo\SecurityAlertsBundle\Notification\NullSender;
use Symfony\Component\DependencyInjection\Compiler\CompilerPassInterface;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Definition;
use Symfony\Component\DependencyInjection\Reference;

/**
 * Picks how alerts are sent once every bundle has registered its services:
 * symfony/notifier if the app configured it, else the mailer, else nobody.
 */
final class SenderPass implements CompilerPassInterface
{
    public function process(ContainerBuilder $container): void
    {
        if (!$container->hasDefinition('security_alerts.checker')) {
            return;
        }

        $settings = new Reference('security_alerts.notify_settings');

        if ($container->has('notifier') && class_exists(NotifierSender::class) && interface_exists(\Symfony\Component\Notifier\NotifierInterface::class)) {
            $sender = new Definition(NotifierSender::class, [new Reference('notifier'), $settings]);
        } elseif ($container->has('mailer.mailer')) {
            $sender = new Definition(MailerSender::class, [new Reference('mailer.mailer'), $settings]);
        } else {
            $sender = new Definition(NullSender::class);
        }

        $container->setDefinition('security_alerts.sender', $sender);
    }
}

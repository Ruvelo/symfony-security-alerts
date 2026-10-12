<?php

declare(strict_types=1);

namespace Ruvelo\SecurityAlertsBundle\Notification;

/**
 * Used when neither symfony/notifier nor symfony/mailer is set up.
 */
final class NullSender implements Sender
{
    public function send(Alert $alert): bool
    {
        return false;
    }
}

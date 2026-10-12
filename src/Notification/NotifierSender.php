<?php

declare(strict_types=1);

namespace Ruvelo\SecurityAlertsBundle\Notification;

use Symfony\Component\Notifier\NotifierInterface;
use Symfony\Component\Notifier\Recipient\Recipient;

/**
 * Sends through symfony/notifier: email to the recipients, and whatever chat
 * channels the app has configured ("chat", "chat/slack"...).
 */
final class NotifierSender implements Sender
{
    public function __construct(private readonly NotifierInterface $notifier, private readonly NotifySettings $settings)
    {
    }

    public function send(Alert $alert): bool
    {
        $channels = $this->settings->channels;
        $sent = false;

        if (\in_array('email', $channels, true) && $this->settings->recipients !== []) {
            $this->notifier->send(
                new AlertNotification($alert, ['email'], $this->settings->from),
                ...array_map(static fn (string $email): Recipient => new Recipient($email), $this->settings->recipients),
            );
            $sent = true;
        }

        $others = array_values(array_filter($channels, static fn (string $c): bool => $c !== 'email'));
        if ($others !== []) {
            $this->notifier->send(new AlertNotification($alert, $others, $this->settings->from));
            $sent = true;
        }

        return $sent;
    }
}

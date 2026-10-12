<?php

declare(strict_types=1);

namespace Ruvelo\SecurityAlertsBundle\Notification;

use Symfony\Component\Mailer\MailerInterface;
use Symfony\Component\Mime\Email;

/**
 * The fallback without symfony/notifier: one email to all recipients.
 */
final class MailerSender implements Sender
{
    public function __construct(private readonly MailerInterface $mailer, private readonly NotifySettings $settings)
    {
    }

    public function send(Alert $alert): bool
    {
        if ($this->settings->recipients === [] || !\in_array('email', $this->settings->channels, true)) {
            return false;
        }

        $email = (new Email())
            ->to(...$this->settings->recipients)
            ->subject($alert->subject())
            ->text(AlertRenderer::text($alert))
            ->html(AlertRenderer::html($alert));

        if ($this->settings->from !== null) {
            $email->from($this->settings->from);
        }

        $this->mailer->send($email);

        return true;
    }
}

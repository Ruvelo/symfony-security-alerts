<?php

declare(strict_types=1);

namespace Ruvelo\SecurityAlertsBundle\Notification;

use Symfony\Component\Mime\Email;
use Symfony\Component\Notifier\Message\ChatMessage;
use Symfony\Component\Notifier\Message\EmailMessage;
use Symfony\Component\Notifier\Notification\ChatNotificationInterface;
use Symfony\Component\Notifier\Notification\EmailNotificationInterface;
use Symfony\Component\Notifier\Notification\Notification;
use Symfony\Component\Notifier\Recipient\EmailRecipientInterface;
use Symfony\Component\Notifier\Recipient\RecipientInterface;

/**
 * The alert as a Notifier notification: a branded email without needing Twig,
 * and plain text for chat channels.
 */
final class AlertNotification extends Notification implements EmailNotificationInterface, ChatNotificationInterface
{
    /**
     * @param list<string> $channels
     */
    public function __construct(public readonly Alert $alert, array $channels, private readonly ?string $from = null)
    {
        parent::__construct($alert->subject(), $channels);

        $this->content(AlertRenderer::text($alert));
        $this->importance($alert->isUrgent() ? self::IMPORTANCE_URGENT : self::IMPORTANCE_HIGH);
    }

    public function asEmailMessage(EmailRecipientInterface $recipient, ?string $transport = null): EmailMessage
    {
        $email = (new Email())
            ->to($recipient->getEmail())
            ->subject($this->alert->subject())
            ->text(AlertRenderer::text($this->alert))
            ->html(AlertRenderer::html($this->alert));

        if ($this->from !== null) {
            $email->from($this->from);
        }

        return new EmailMessage($email);
    }

    public function asChatMessage(RecipientInterface $recipient, ?string $transport = null): ChatMessage
    {
        return new ChatMessage($this->alert->subject()."\n\n".AlertRenderer::text($this->alert));
    }
}

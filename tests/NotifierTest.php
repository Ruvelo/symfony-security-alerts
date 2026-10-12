<?php

declare(strict_types=1);

namespace Ruvelo\SecurityAlertsBundle\Tests;

use Ruvelo\SecurityAlertsBundle\Notification\NotifierSender;
use Symfony\Component\Mime\Email;

/**
 * With symfony/notifier configured, alerts go through it: email via the
 * mailer, and whatever chat channels the app set up.
 */
final class NotifierTest extends BundleTestCase
{
    /**
     * @return array<string, mixed>
     */
    private function notifier(): array
    {
        return [
            'mailer' => ['dsn' => 'null://null'],
            'notifier' => ['chatter_transports' => ['main' => 'null://null']],
        ];
    }

    public function testTheNotifierIsUsedWhenTheAppConfiguredIt(): void
    {
        $this->boot([], $this->notifier());

        self::assertInstanceOf(NotifierSender::class, self::getContainer()->get('security_alerts.sender'));
    }

    public function testEmailGoesThroughTheNotifierAsTheBrandedMessage(): void
    {
        $this->boot([], $this->notifier());
        $this->console(['--notify' => true]);

        self::assertEmailCount(1);
        $email = self::getMailerMessage();
        self::assertInstanceOf(Email::class, $email);
        self::assertSame('Halyard: exploited vulnerability in livewire/livewire, patch today', $email->getSubject());
        self::assertSame('ops@example.com', $email->getTo()[0]->getAddress());
        self::assertSame('alerts@example.com', $email->getFrom()[0]->getAddress());
        self::assertStringContainsString('Update to 3.6.4 or later', (string) $email->getHtmlBody());
        self::assertStringContainsString('A vulnerability in Halyard is being exploited', (string) $email->getTextBody());
        self::assertNotificationCount(0, null, 'No chat channel was asked for.');
    }

    public function testChatChannelsGetOneMessageWithoutRecipients(): void
    {
        $this->boot(['notify' => ['recipients' => ['a@example.com', 'b@example.com'], 'from' => 'alerts@example.com', 'channels' => ['email', 'chat'], 'app_name' => 'Halyard']], $this->notifier());
        $this->console(['--notify' => true]);

        self::assertEmailCount(2);
        self::assertNotificationCount(1);
        $chat = self::getNotifierMessage();
        self::assertNotNull($chat);
        self::assertStringContainsString('Halyard: exploited vulnerability in livewire/livewire, patch today', $chat->getSubject());
        self::assertStringContainsString('CVE-2025-54068', $chat->getSubject());
    }

    public function testChatAloneNeedsNoRecipients(): void
    {
        $this->boot(['notify' => ['recipients' => [], 'channels' => ['chat'], 'app_name' => 'Halyard']], $this->notifier());

        [$code, $output] = $this->console(['--notify' => true]);

        self::assertSame(0, $code);
        self::assertStringContainsString('Sent an alert about 11 findings.', $output);
        self::assertEmailCount(0);
        self::assertNotificationCount(1);
    }

    public function testNothingIsSentTwice(): void
    {
        $this->boot(['notify' => ['recipients' => ['a@example.com'], 'from' => 'alerts@example.com', 'channels' => ['email', 'chat']]], $this->notifier());
        $this->console(['--notify' => true]);
        $this->console(['--notify' => true]);

        self::assertEmailCount(1);
        self::assertNotificationCount(1);
    }

    public function testWithoutNotifierOrMailerNobodyCanBeTold(): void
    {
        $this->boot([], ['mailer' => ['enabled' => false]]);

        [$code, $output] = $this->console(['--notify' => true]);

        self::assertSame(0, $code);
        self::assertStringContainsString('nobody was told', $output);
    }
}

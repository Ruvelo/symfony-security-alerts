<?php

declare(strict_types=1);

namespace Ruvelo\SecurityAlertsBundle\Tests;

use Ruvelo\SecurityAlertsBundle\Schedule\CheckMessage;
use Ruvelo\SecurityAlertsBundle\Schedule\CheckMessageHandler;
use Ruvelo\SecurityAlertsBundle\Schedule\SecurityAlertsSchedule;
use Symfony\Component\Messenger\MessageBusInterface;

final class ScheduleTest extends BundleTestCase
{
    /**
     * @return array<string, mixed>
     */
    private function messenger(): array
    {
        return ['messenger' => ['enabled' => true], 'mailer' => ['dsn' => 'null://null']];
    }

    public function testADailyScheduleIsRegisteredWithTheSchedulerComponent(): void
    {
        $this->boot(['schedule' => ['time' => '06:30', 'timezone' => 'UTC']], $this->messenger());

        $container = self::getContainer();
        self::assertTrue($container->has('messenger.transport.scheduler_security_alerts'), 'The scheduler component built a transport named after the provider.');

        $provider = new SecurityAlertsSchedule('06:30', 'UTC');
        $messages = $provider->getSchedule()->getRecurringMessages();
        self::assertCount(1, $messages);
    }

    public function testItRunsDailyAtTheConfiguredTime(): void
    {
        $message = SecurityAlertsSchedule::message('06:30', 'UTC');
        $trigger = $message->getTrigger();

        $after = new \DateTimeImmutable('2026-10-12 08:00:00', new \DateTimeZone('UTC'));
        self::assertSame('2026-10-13 06:30', $trigger->getNextRunDate($after)?->format('Y-m-d H:i'));

        $before = new \DateTimeImmutable('2026-10-12 05:00:00', new \DateTimeZone('UTC'));
        self::assertSame('2026-10-12 06:30', $trigger->getNextRunDate($before)?->format('Y-m-d H:i'));
    }

    public function testTheHandlerRunsAnAnnouncingCheck(): void
    {
        $this->boot([], $this->messenger());

        $handler = self::getContainer()->get('security_alerts.schedule.handler');
        self::assertInstanceOf(CheckMessageHandler::class, $handler);
        $handler(new CheckMessage());

        self::assertEmailCount(1);
    }

    public function testTheMessageBusRoutesTheMessageToTheHandler(): void
    {
        $this->boot([], $this->messenger());

        $bus = self::getContainer()->get(MessageBusInterface::class);
        self::assertInstanceOf(MessageBusInterface::class, $bus);
        $bus->dispatch(new CheckMessage());

        self::assertEmailCount(1);
    }

    public function testItCanBeTurnedOff(): void
    {
        $this->boot(['schedule' => ['enabled' => false]], $this->messenger());

        self::assertFalse(self::getContainer()->has('messenger.transport.scheduler_security_alerts'));
    }

    public function testWithoutMessengerNothingIsRegisteredAndNothingBreaks(): void
    {
        $this->boot();

        self::assertFalse(self::getContainer()->has('security_alerts.schedule'));
    }
}

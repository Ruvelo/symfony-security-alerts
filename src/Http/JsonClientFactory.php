<?php

declare(strict_types=1);

namespace Ruvelo\SecurityAlertsBundle\Http;

use Nyholm\Psr7\Factory\Psr17Factory;
use Ruvelo\SecurityAdvisories\Http\JsonClient;
use Symfony\Component\HttpClient\HttpClient;
use Symfony\Component\HttpClient\Psr18Client;
use Symfony\Contracts\HttpClient\HttpClientInterface;

/**
 * The core's JsonClient on Symfony's HttpClient, through its PSR-18 adapter.
 */
final class JsonClientFactory
{
    public static function create(?HttpClientInterface $client, float $timeout = 15.0, int $tries = 2): JsonClient
    {
        $client = ($client ?? HttpClient::create())->withOptions(['timeout' => $timeout, 'max_duration' => $timeout * 4]);
        $factory = new Psr17Factory();

        return new JsonClient(new Psr18Client($client, $factory, $factory), $factory, $factory, tries: $tries);
    }
}

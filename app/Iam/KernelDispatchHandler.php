<?php

namespace App\Iam;

use GuzzleHttp\Promise\Create;
use GuzzleHttp\Promise\PromiseInterface;
use GuzzleHttp\Psr7\Response as Psr7Response;
use Psr\Http\Message\RequestInterface;
use Symfony\Component\HttpFoundation\Request as SymfonyRequest;

/**
 * DEMO ONLY — a Guzzle handler that dispatches the request into THIS app's HTTP kernel instead of
 * the network. The demo runs server and resource server in one single-threaded app (`artisan
 * serve`): a real HTTP self-call would deadlock, so the introspection performed by the client
 * SDK's DelegatedTokenVerifier travels through an internal sub-request — same route, same
 * controller, same league server, zero mocks. In production the resource server introspects the
 * IAM host over real HTTPS and this class does not exist.
 */
class KernelDispatchHandler
{
    /** @param array<string, mixed> $options */
    public function __invoke(RequestInterface $request, array $options): PromiseInterface
    {
        $params = [];
        $body = (string) $request->getBody();
        if ($body !== '' && str_contains($request->getHeaderLine('Content-Type'), 'application/x-www-form-urlencoded')) {
            parse_str($body, $params);
        }

        $sub = SymfonyRequest::create((string) $request->getUri(), $request->getMethod(), $params);
        foreach ($request->getHeaders() as $name => $values) {
            $sub->headers->set($name, $values);
        }

        $response = app()->handle($sub);

        return Create::promiseFor(new Psr7Response(
            $response->getStatusCode(),
            $response->headers->all(),
            (string) $response->getContent(),
        ));
    }
}

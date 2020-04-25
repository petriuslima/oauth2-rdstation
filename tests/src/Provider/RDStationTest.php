<?php

namespace Petriuslima\OAuth2\Client\Tests\Provider;

class RDStationTest extends \PHPUnit\Framework\TestCase
{
    public function setUp(): void
    {
        $this->provider = new \Petriuslima\OAuth2\Client\Provider\RDStation([
            'clientId' => 'mock_client_id',
            'clientSecret' => 'mock_secret',
            'redirectUrl' => 'none',
        ]);
    }

    public function testAuthorizationUrl()
    {
        $url = $this->provider->getAuthorizationUrl();
        $uri = parse_url($url);
        parse_str($uri['query'], $query);

        $this->assertArrayHasKey('client_id', $query);
        $this->assertArrayHasKey('redirect_url', $query);
        $this->assertArrayHasKey('state', $query);
        $this->assertArrayHasKey('scope', $query);
        $this->assertArrayHasKey('response_type', $query);
        $this->assertArrayHasKey('approval_prompt', $query);
        $this->assertNotNull($this->provider->getState());
    }

    public function testSetHostInConfig()
    {
        $host = uniqid();

        $provider = new \Petriuslima\OAuth2\Client\Provider\RDStation([
            'clientId' => 'mock_client_id',
            'clientSecret' => 'mock_secret',
            'redirectUrl' => 'none',
            'host' => $host
        ]);

        $this->assertEquals($host, $provider->getHost());
    }

    public function testGetAuthorizationUrl()
    {
        $url = $this->provider->getAuthorizationUrl();
        $uri = parse_url($url);

        $this->assertEquals('/auth/dialog', $uri['path']);
    }

    public function testGetBaseAccessTokenUrl()
    {
        $params = [];

        $url = $this->provider->getBaseAccessTokenUrl($params);
        $uri = parse_url($url);

        $this->assertEquals('/auth/token', $uri['path']);
    }
}

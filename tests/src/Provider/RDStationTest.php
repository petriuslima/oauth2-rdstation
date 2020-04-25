<?php

namespace Petriuslima\OAuth2\Client\Tests\Provider;

use Mockery as m;

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

    public function testGetAccessToken()
    {
        $response = m::mock('Psr\Http\Message\ResponseInterface');
        $response->shouldReceive('getBody')->andReturn('{"access_token":"mock_access_token","user_id": "123"}');
        $response->shouldReceive('getHeader')->andReturn(['content-type' => 'json']);

        $client = m::mock('GuzzleHttp\ClientInterface');
        $client->shouldReceive('send')->times(1)->andReturn($response);
        $this->provider->setHttpClient($client);

        $token = $this->provider->getAccessToken('authorization_code', ['code' => 'mock_authorization_code']);

        $this->assertEquals('mock_access_token', $token->getToken());
        $this->assertNull($token->getExpires());
        $this->assertNull($token->getRefreshToken());
    }
}

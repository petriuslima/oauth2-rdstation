<?php

namespace Petriuslima\OAuth2\Client\Provider;

use League\OAuth2\Client\Provider\AbstractProvider;
use League\OAuth2\Client\Tool\BearerAuthorizationTrait;
use League\OAuth2\Client\Token\AccessToken;
use League\OAuth2\Client\Provider\Exception\IdentityProviderException;
use Psr\Http\Message\ResponseInterface;

class RDStation extends AbstractProvider
{
    use BearerAuthorizationTrait;

    protected $host = 'https://api.rd.services';

    protected $redirectUrl;

    private $responseError = 'error';

    public function getHost()
    {
        return $this->host;
    }

    public function getBaseAuthorizationUrl()
    {
        return $this->host . '/auth/dialog';
    }

    public function getBaseAccessTokenUrl(array $params)
    {
        return $this->host . '/auth/token';
    }

    public function getResourceOwnerDetailsUrl(AccessToken $token)
    {
        return '';
    }

    protected function getDefaultScopes()
    {
        return [];
    }

    public function getAccessToken($grant, array $options = [])
    {
        // Copy parent method to replace request_uri to request_url

        $grant = $this->verifyGrant($grant);

        $params = [
            'client_id'     => $this->clientId,
            'client_secret' => $this->clientSecret,
            'redirect_url'  => $this->redirectUrl,
        ];

        $params   = $grant->prepareRequestParameters($params, $options);
        $request  = $this->getAccessTokenRequest($params);
        $response = $this->getParsedResponse($request);

        if (false === is_array($response)) {
            throw new UnexpectedValueException(
                'Invalid response received from Authorization Server. Expected JSON.'
            );
        }

        $prepared = $this->prepareAccessTokenResponse($response);
        $token    = $this->createAccessToken($prepared, $grant);

        return $token;
    }

    protected function getAuthorizationParameters(array $options)
    {
        // Copy parent method to replace request_uri to request_url

        if (empty($options['state'])) {
            $options['state'] = $this->getRandomState();
        }

        if (empty($options['scope'])) {
            $options['scope'] = $this->getDefaultScopes();
        }

        $options += [
            'response_type'   => 'code',
            'approval_prompt' => 'auto'
        ];

        if (is_array($options['scope'])) {
            $separator = $this->getScopeSeparator();
            $options['scope'] = implode($separator, $options['scope']);
        }

        // Store the state as it may need to be accessed later on.
        $this->state = $options['state'];

        // Business code layer might set a different redirect_url parameter
        // depending on the context, leave it as-is
        if (!isset($options['redirect_url'])) {
            $options['redirect_url'] = $this->redirectUrl;
        }

        $options['client_id'] = $this->clientId;

        return $options;
    }

    protected function checkResponse(ResponseInterface $response, $data)
    {
        if (!empty($data[$this->responseError])) {
            $error = $data[$this->responseError];

            if (!is_string($error)) {
                $error = var_export($error, true);
            }

            $code  = $this->responseCode && !empty($data[$this->responseCode])? $data[$this->responseCode] : 0;

            if (!is_int($code)) {
                $code = intval($code);
            }

            throw new IdentityProviderException($error, $code, $data);
        }
    }

    protected function createResourceOwner(array $response, AccessToken $token)
    {
        return new \stdClass();
    }
}

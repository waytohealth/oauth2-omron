<?php

namespace waytohealth\OAuth2\Client\Provider;

use Exception;
use League\OAuth2\Client\Provider\AbstractProvider;
use League\OAuth2\Client\Provider\GenericResourceOwner;
use League\OAuth2\Client\Provider\Exception\IdentityProviderException;
use League\OAuth2\Client\Tool\BearerAuthorizationTrait;
use Psr\Http\Message\ResponseInterface;

class Omron extends AbstractProvider
{
    use BearerAuthorizationTrait;

    /**
     * @var string
     */
    protected $authHostname;

    /**
     * @var string Key used in a token response to identify the resource owner.
     */
    const ACCESS_TOKEN_RESOURCE_OWNER_ID = 'sub';

    /**
     * Get authorization url to begin OAuth flow.
     *
     * @return string
     */
    public function getBaseAuthorizationUrl()
    {
        return $this->authHostname . '/connect/authorize';
    }

    /**
     * Get access token url to retrieve token.
     *
     * @param array $params
     *
     * @return string
     */
    public function getBaseAccessTokenUrl(array $params)
    {
        return $this->authHostname . '/connect/token';
    }

    /**
     * Returns all scopes available from Omron.
     * It is recommended you only request the scopes you need!
     *
     * @return array
     */
    protected function getDefaultScopes()
    {
        return ['openid', 'offline_access', 'bloodpressure'];
    }
    protected function getScopeSeparator()
    {
        return ' ';
    }

    protected function getDefaultHeaders()
    {
        return ['Content-Type' => 'application/x-www-form-urlencoded'];
    }

    /**
     * Checks Omron API response for errors.
     *
     * @throws IdentityProviderException
     *
     * @param ResponseInterface $response
     * @param array|string      $data     Parsed response data
     */
    protected function checkResponse(ResponseInterface $response, $data)
    {
        if (array_key_exists('error', $data)) {
            $errorMessage = $data['error'];
            $errorCode = array_key_exists('status', $data) ?
                $data['status'] : $response->getStatusCode();
            throw new IdentityProviderException(
                $errorMessage,
                $errorCode,
                $data
            );
        }
    }

    /**
     * Returns authorization parameters based on provided options.
     * Omron does not use the 'approval_prompt' param and here we remove it.
     *
     * @param array $options
     *
     * @return array Authorization parameters
     */
    protected function getAuthorizationParameters(array $options)
    {
        $params = parent::getAuthorizationParameters($options);
        unset($params['approval_prompt']);
        if (!empty($options['prompt'])) {
            $params['prompt'] = $options['prompt'];
        }

        return $params;
    }

    public function getResourceOwnerDetailsUrl(\League\OAuth2\Client\Token\AccessToken $token)
    {
        return '';
    }

    /**
     * Generates a resource owner object from a successful resource owner
     * details request.
     *
     * @param array       $response
     * @param AccessToken $token
     *
     * @return GenericResourceOwner
     */
    public function createResourceOwner(array $response, \League\OAuth2\Client\Token\AccessToken $token)
    {
        return new GenericResourceOwner($response, self::ACCESS_TOKEN_RESOURCE_OWNER_ID);
    }

    /**
     * Revoke access for the given token.
     *
     * @param OmronAccessToken $accessToken
     *
     * @return mixed
     */
    public function revoke(\League\OAuth2\Client\Token\AccessToken $accessToken)
    {
        $options = $this->optionProvider->getAccessTokenOptions($this->getAccessTokenMethod(), []);
        $uri = $this->appendQuery(
            $this->authHostname . '/connect/revocation',
            $this->buildQueryString(['token' => $accessToken->getToken(), 'token_type_hint' => 'access_token'])
        );
        $request = $this->getRequest(self::METHOD_POST, $uri, $options);

        return $this->getResponse($request);
    }

    public function parseResponse(ResponseInterface $response)
    {
        return parent::parseResponse($response);
    }
}
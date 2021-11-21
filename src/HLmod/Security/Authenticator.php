<?php

namespace App\HLmod\Security;

use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Generator\UrlGeneratorInterface;
use Symfony\Component\Routing\RouterInterface;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\Exception\CustomUserMessageAuthenticationException;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Core\User\UserProviderInterface;
use Symfony\Component\Security\Guard\AbstractGuardAuthenticator;
use Symfony\Contracts\HttpClient\HttpClientInterface;


class Authenticator extends AbstractGuardAuthenticator
{
    private $router;
    private $httpClient;

    private $clientId;
    private $clientSecret;

    public function __construct(RouterInterface $router,
        int $oauthClientId, string $oauthClientSecret, HttpClientInterface $httpClient)
    {
        $this->router = $router;
        $this->httpClient = $httpClient;

        $this->clientId = $oauthClientId;
        $this->clientSecret = $oauthClientSecret;
    }

    public function supports(Request $request)
    {
        return $request->attributes->get('_route') === 'login' && $request->query->get('code');
    }

    public function getCredentials(Request $request)
    {
        $code = $request->get('code');
        if (!$code)
        {
            throw new CustomUserMessageAuthenticationException('User cancelled the authorization');
        }

        $response = $this->httpClient->request('GET', 'https://hlmod.ru/api/auth/hlm-oauth/token/', [
            'query' => [
                'client_id' => $this->clientId,
                'client_secret' => $this->clientSecret,

                'grant_type' => 'authorization_code',
                'code' => $code,
                'redirect_uri' => $this->router->generate('login', [], UrlGeneratorInterface::ABSOLUTE_URL)
            ]
        ]);

        if ($response->getStatusCode() !== 200)
        {
            throw new CustomUserMessageAuthenticationException('Invalid code');
        }

        $body = json_decode($response->getContent(), true);
        return $body['user_id'];
    }

    public function start(Request $request, AuthenticationException $authException = null)
    {
        $currentReturn = $request->getPathInfo();
        $currentQueryString = $request->getQueryString();
        if (!empty($currentQueryString))
        {
            $currentReturn .= '?' . $currentQueryString;
        }

        $returnTo = $this->router->generate('login', [
            'return' => $request->get('return', $currentReturn)
        ], UrlGeneratorInterface::ABSOLUTE_URL);

        $url = 'https://hlmod.ru/login/oauth/';
        $params = [
            'client_id' => $this->clientId,
            'scope' => 'user:read',
            'response_type' => 'code',
            'redirect_uri' => $returnTo
        ];

        return new RedirectResponse($url . '?' . http_build_query($params));
    }

    public function getUser($credentials, UserProviderInterface $userProvider)
    {
        return $userProvider->loadUserByUsername($credentials);
    }

    public function checkCredentials($credentials, UserInterface $user)
    {
        return true;
    }

    public function onAuthenticationFailure(Request $request, AuthenticationException $exception)
    {
        return $this->performRedirect($request, $this->router->generate('index'));
    }

    public function onAuthenticationSuccess(Request $request, TokenInterface $token, $providerKey)
    {
        return $this->performRedirect($request, $this->router->generate('dashboard'));
    }

    public function supportsRememberMe()
    {
        return true;
    }

    /**
     * @param Request $request
     * @param $defaultUrl
     * @return RedirectResponse
     */
    protected function performRedirect(Request $request, $defaultUrl): RedirectResponse
    {
        $returnUrl = $request->get('return', $defaultUrl);
        return new RedirectResponse($returnUrl);
    }
}

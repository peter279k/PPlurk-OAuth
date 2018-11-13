<?php

namespace PPlurk\OAuth;

use GuzzleHttp\Client;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Subscriber\Oauth\Oauth1;

class PlurkOAuth
{
    const REQUEST_TOKEN_URL = 'https://www.plurk.com/OAuth/request_token';
    const AUTHORIZE_URL = 'https://www.plurk.com/OAuth/authorize';
    const AUTHORIZE_URL_FOR_MOBILE = 'https://www.plurk.com/m/authorize';
    const ACCESS_TOKEN_URL = 'https://www.plurk.com/OAuth/access_token';

    private $setting;

    /**
     * Create a PlurkOAuth object.
     *
     * @param string $appKey Consumer key string. Can not be empty.
     * @param string $appSecret Consumer secret. Can not be empty.
     * @param string $token Client token.
     * @param string $tokenSecret Client secret token.
     */
    public function __construct($appKey, $appSecret, $token = '', $tokenSecret = '')
    {
        if (empty($appKey) || empty($appSecret)) {
            throw new InvalidArgumentException("appKey and appSecret can not be empty");
        }

        $this->setting = array(
            'consumer_key' => $appKey,
            'consumer_secret' => $appSecret,
        );

        $this->setting['token'] = $token;
        $this->setting['token_secret'] = $tokenSecret;
    }

    /**
     * Call api by post
     *
     * @param string $target API target
     * @param array $params params what is need to pass
     * @return GuzzleHttp\Psr7\Response Api response
     */
    public function post($target, $params = array())
    {
        $client = $this->getGuzzleClient();
        return $client->request('POST', $target, [
            'form_params' => $params,
        ]);
    }

    /**
     * Call api by get
     *
     * @param string $target API target
     * @return GuzzleHttp\Psr7\Response Api response
     */
    public function get($target)
    {
        $client = $this->getGuzzleClient();
        return $client->get($target);
    }

    /**
     * Direct user for authorization
     */
    public function startAuth()
    {
        $res = $this->getRequestToken();

        $_SESSION['oauth_token'] = $res['oauth_token'];
        $_SESSION['oauth_token_secret'] = $res['oauth_token_secret'];
        if ($this->isMobile()) {
            header("Location: " . self::AUTHORIZE_URL_FOR_MOBILE . "?oauth_token=" . $res['oauth_token']);
        } else {
            header("Location: " . self::AUTHORIZE_URL . "?oauth_token=" . $res['oauth_token']);
        }
    }

    /**
     * Receive tokens.
     *
     * @return array Values which oauth response.
     */
    public function parseCallback()
    {
        $responseToken = $_GET['oauth_token'];
        $verifier = $_GET['oauth_verifier'];

        if ($responseToken !== $_SESSION['oauth_token']) {
            throw new \Exception('oauth_token dose not match.');
        }

        $this->setting['token'] = $_SESSION['oauth_token'];
        $this->setting['token_secret'] = $_SESSION['oauth_token_secret'];
        $this->setting['verifier'] = $verifier;

        return $this->getAccessToken();
    }

    private function getRequestToken()
    {
        $stack = HandlerStack::create();

        $middleware = new Oauth1($this->setting);
        $stack->push($middleware);

        $client = new Client([
            'handler' => $stack,
            'auth' => 'oauth',
        ]);

        $res = (string) $client->request('GET', self::REQUEST_TOKEN_URL)->getBody();
        return $this->parseOAuthRespose($res);
    }

    private function getAccessToken()
    {
        $stack = HandlerStack::create();

        $middleware = new Oauth1($this->setting);
        $stack->push($middleware);

        $client = new Client([
            'handler' => $stack,
            'auth' => 'oauth',
        ]);

        $res = (string) $client->request('GET', self::ACCESS_TOKEN_URL)->getBody();
        return $this->parseOAuthRespose($res);
    }

    private function parseOAuthRespose($res)
    {
        $resExploded = \explode('&', $res);
        $resArray = array();
        foreach ($resExploded as $value) {
            $parsedString = \explode('=', $value);
            $resArray[$parsedString[0]] = $parsedString[1];
        }
        return $resArray;
    }

    private function getGuzzleClient()
    {
        $stack = HandlerStack::create();

        $middleware = new Oauth1($this->setting);
        $stack->push($middleware);

        $client = new Client([
            'base_uri' => 'https://www.plurk.com/APP/',
            'handler' => $stack,
            'auth' => 'oauth',
        ]);

        return $client;
    }

    private function isMobile()
    {
        return preg_match("/(android|avantgo|blackberry|bolt|boost|cricket|docomo|fone|hiptop|mini|mobi|palm|phone|pie|tablet|up\.browser|up\.link|webos|wos)/i", $_SERVER["HTTP_USER_AGENT"]);
    }
}

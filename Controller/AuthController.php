<?php

namespace Bangpound\Bundle\SatellizerBundle\Controller;

use OAuth2\OAuth2;
use Symfony\Bundle\FrameworkBundle\Controller\Controller;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpKernel\HttpKernelInterface;

/**
 * Class AuthController
 * @package Bangpound\Bundle\SatellizerBundle\Controller
 */
class AuthController extends Controller
{
    /**
     * @param  Request $request
     * @return mixed
     */
    public function providerAction(Request $request)
    {
        $repo = $this->getDoctrine()->getRepository('Bangpound\\Bundle\\UserBundle\\Entity\\Client');
        $data = json_decode($request->getContent(), true);

        $client = $repo->find($data['clientId']);

        $params = array(
            'code' => $data['code'],
            'client_id' => $data['clientId'],
            'redirect_uri' => $data['redirectUri'],
            'grant_type' => OAuth2::GRANT_TYPE_AUTH_CODE,
            'client_secret' => $client->getSecret(),
        );

        // Step 1. Exchange authorization code for access token.
        $subrequest = new Request($params, array(), array('_controller' => 'fos_oauth_server.controller.token:tokenAction'));
        $subresponse = $this->get('http_kernel')->handle($subrequest, HttpKernelInterface::SUB_REQUEST);

        $repo = $this->getDoctrine()->getRepository('BangpoundUserBundle:AccessToken');
        $data = json_decode($subresponse->getContent(), true);
        $authCode = $repo->findOneByToken($data['access_token']);

        $payload = array(
            'iss' => $request->getBaseUrl(),
            'sub' => $authCode->getUser()->getId(),
            'iat' => time(),
            'exp' => time() + (2 * 7 * 24 * 60 * 60)
        );

        $key = $this->container->getParameter('kernel.secret');

        return JsonResponse::create(array('token' => \JWT::encode($payload, $key)));
    }
}

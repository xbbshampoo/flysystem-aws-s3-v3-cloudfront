<?php

namespace League\Flysystem\AwsS3V3;

use DateTime;
use GuzzleHttp\Psr7\Uri;

/**
 * @internal
 */
class HmacSigner
{
    /**
     * @var string  Keypair id
     */
    private $keyPairId;

    /**
     * @var string  Passphrase for hmac
     */
    private $passphrase;

    /**
     * A signer for creating the signature values used in CloudFront distributor custom
     * cloudfront function hmac-urlsign-verify to authorize the access.
     *
     * @param $keyPairId  string ID of the key pair
     * @param $passphrase string used to generate hmac
     * @param $algo       string hmac algo to generate hash
     *
     * @throws \InvalidArgumentException if all mandatory arguments are not passed.
     */
    public function __construct($keyPairId, $passphrase)
    {
        if (empty($keyPairId) || empty($passphrase)) {
            throw new \InvalidArgumentException('keyPairId, passphrase, algo are mandatory');
        }

        $this->keyPairId = $keyPairId;
        $this->passphrase = $passphrase;
    }

    /**
     * Create a signed Amazon CloudFront URL for custom hmac-urlsign-verify cloudfront function.
     *
     * @param string              $uri     URL to sign (can include query
     *                                     string string)
     * @param string|integer|null $expires UTC Unix timestamp used.
     * @param string              $payload JSON payload. Use this option when
     *                                     creating a signature for a custom
     *                                     response headers or query param to
     *                                     pass  to origin.
     *
     * @return string The file URL with authentication parameters
     * @throws \InvalidArgumentException if the URL or expires provided is invalid
     * @link   https://github.com/Iconscout/cloudfront-functions
     */
    public function getSignedUrl($url, $expires = null, $payload = [])
    {
        if (!($url && $expires)) {
            throw new \InvalidArgumentException('Uri and Expires are required.');
        }

        // Determine the scheme of the url
        $urlSections = explode('://', $url);
        if (count($urlSections) < 2) {
            throw new \InvalidArgumentException("Invalid URL: {$url}");
        }

        $uri = new Uri($url);
        $signature = $this->getSignature(
            $uri,
            $expires,
            $payload
        );
        $uri = $uri->withQuery(
            http_build_query(['token' => $signature], '', '&', PHP_QUERY_RFC3986)
        );

        return (string) $uri;
    }

    /**
     * Create the values used to construct signed URLs and cookies.
     *
     * @param Uri                 $uri     URL to sign (can include query
     *                                     string string)
     * @param string|integer|null $expires UTC Unix timestamp used.
     * @param string              $payload JSON payload. Use this option when
     *                                     creating a signature for a custom
     *                                     response headers or query param to
     *                                     pass  to origin.
     *
     * @return string The signature token
     * @throws \InvalidArgumentException  when not provided either uri or expire.
     *
     * @link https://github.com/Iconscout/cloudfront-functions
     */
    public function getSignature($uri, $expires, $payload = [])
    {
        parse_str($uri->getQuery(), $query);
        $payloadSeg = $this->createPayloadSegment((int) $expires, $uri->getHost(), $query, $payload);
        return $this->token($uri->getPath(), $payloadSeg);
    }

    public function verifySignatureUrl($url, $keyId, $passphrase)
    {
        $uri = new Uri($url);

        parse_str($uri->getQuery(), $query);
        $token = $query['token'];
        if (!$token) {
            throw new \InvalidArgumentException('No token supplied');
        }

        // check segments
        $segments = explode('.', $token);
        if (count($segments) !== 3) {
            throw new \Exception('Not enough or too many segments');
        }

        $headerSeg = $segments[0];
        $payloadSeg = $segments[1];
        $signatureSeg = $segments[2];

        $header = json_decode($this->decode($headerSeg));
        if ($header->kid !== $keyId) {
            throw new \Exception('Provided keyid does not match with token header kid.');
        }

        $signatureInput = $uri->getPath() . PHP_EOL . $headerSeg . '.' . $payloadSeg;

        $sign = $this->sign($signatureInput, $this->getAlgo($header->alg), $passphrase);

        if ($sign !== $signatureSeg) {
            throw new \Exception('Signature verification failed.');
        }

        $payload = json_decode($this->decode($payloadSeg));

        if ((new DateTime())->getTimestamp() - (int) $payload->exp > 0) {
            throw new \Exception('Token is expired');
        }

        // TODO: should we validate host
        return (array) $payload;
    }

    private function createPayloadSegment($expires, $host, $query, $payload)
    {
        $q = [];
        foreach ($query as $key => $value) {
            $q[$key] = [];
            $q[$key]['value'] = $value;
        }

        if (empty($q)) {
            $q = null;
        }

        $payloadArr = array_merge(
            ['iss' => $host, 'exp' => $expires, 'q' => $q, 'iat' => (new DateTime())->getTimestamp()],
            $payload
        );

        return $this->encode(json_encode($payloadArr));
    }

    private function token($path, $payloadSeg)
    {
        $headerSeg = $this->encode(json_encode(['alg' => 'hs256', 'kid' => $this->keyPairId]));
        $signatureSeg = $path . PHP_EOL . $headerSeg . '.' . $payloadSeg;

        $sign = $this->sign($signatureSeg, 'sha256', $this->passphrase);
        return join('.', [$headerSeg, $payloadSeg, $sign]);
    }

    private function sign($signatureSeg, $algo, $passphrase)
    {
        return hash_hmac($algo, $signatureSeg, $passphrase);
    }

    private function getAlgo($alg)
    {
        switch ($alg) {
            case 'hs256':
                return 'sha256';
            default:
                throw new \Exception('Unsupported algorithm');
        }
    }

    private function encode($str)
    {
        return strtr(base64_encode($str), '+=/', '-_~');
    }

    private function decode($str)
    {
        return base64_decode($str);
    }
}
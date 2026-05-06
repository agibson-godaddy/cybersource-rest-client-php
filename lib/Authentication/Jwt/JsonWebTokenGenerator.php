<?php
/*
*Purpose : calling the JWT and generate the token 
*/
namespace CyberSource\Authentication\Jwt;
use CyberSource\Authentication\PayloadDigest\PayloadDigest as PayloadDigest;
use CyberSource\Authentication\Core\TokenGenerator as TokenGenerator;
use CyberSource\Authentication\Core\AuthException as AuthException;
use CyberSource\Authentication\Util\GlobalParameter as GlobalParameter;
use CyberSource\Logging\LogFactory as LogFactory;
use CyberSource\Authentication\Util\MLEUtility as MLEUtility;
use Firebase\JWT\JWT as JWT;
use CyberSource\Authentication\Util\Cache as Cache;
use Ramsey\Uuid\Uuid;

//calling the interface
class JsonWebTokenGenerator implements TokenGenerator
{
    private static $logger = null;
    private static $cache = null;
    
    /**
     * Constructor
     */
    public function __construct(\CyberSource\Logging\LogConfiguration $logConfig)
    {
        if (self::$logger === null) {
            self::$logger = (new LogFactory())->getLogger(\CyberSource\Utilities\Helpers\ClassHelper::getClassName(get_class($this)), $logConfig);
        }

        self::$cache = new Cache();
    }

    //calling Signature
    public function generateToken($resourcePath, $payloadData, $method, $merchantConfig, $isResponseMLEForAPI=false)
    {
        $jwtPayload = $this->getPayloadClaimSet($resourcePath, $payloadData, $method, $merchantConfig, $isResponseMLEForAPI);
        $headerClaimSet = $this->getHeaderClaimSet();

        if ($merchantConfig->getJwtSigningMethod() === GlobalParameter::JWT_SIGNING_SHARED_SECRET) {
            $generatedToken = $this->signWithSharedSecret($jwtPayload, $headerClaimSet, $merchantConfig);
        } else {
            $generatedToken = $this->signWithP12Certificate($jwtPayload, $headerClaimSet, $merchantConfig);
        }

        self::$logger->close();
        return "Bearer ".$generatedToken;
    }

    private function signWithP12Certificate($jwtPayload, $headerClaimSet, $merchantConfig)
    {
        try {
            $cacheData = self::$cache->grabFileFromP12($merchantConfig);
        } catch (AuthException $e) {
            self::$logger->error("Failed to grab file from P12: " . $e->getMessage());
            throw $e;
        }

        if (!empty($cacheData['private_key']) && !empty($cacheData['x509_certificate'])) {
            $privateKey = $cacheData['private_key'];
            $x509Certificate = $cacheData['x509_certificate'];
        } else {
            self::$logger->error("AuthException: " . GlobalParameter::EMPTY_PRIVATE_OR_PUBLIC_KEY_ERROR);
            throw new AuthException("AuthException: " . GlobalParameter::EMPTY_PRIVATE_OR_PUBLIC_KEY_ERROR);
        }

        $kid = strval($this->extractSerialNumber($x509Certificate));
        return JWT::encode($jwtPayload, $privateKey, GlobalParameter::RS256, $kid, $headerClaimSet);
    }

    private function signWithSharedSecret($jwtPayload, $headerClaimSet, $merchantConfig)
    {
        $algorithm = $merchantConfig->getJwtSharedSecretAlgorithm();
        if (!in_array($algorithm, GlobalParameter::SUPPORTED_JWT_SHARED_SECRET_ALGS, true)) {
            self::$logger->error("AuthException: " . GlobalParameter::JWT_SHARED_SECRET_INVALID_ALG);
            throw new AuthException("AuthException: " . GlobalParameter::JWT_SHARED_SECRET_INVALID_ALG);
        }

        $kid = $merchantConfig->getApiKeyID();
        if (empty($kid)) {
            self::$logger->error("AuthException: " . GlobalParameter::JWT_SHARED_SECRET_KEY_ID_REQ);
            throw new AuthException("AuthException: " . GlobalParameter::JWT_SHARED_SECRET_KEY_ID_REQ);
        }

        // The shared secret value is base64-encoded in the Business Center; decode it before
        // using it as an HMAC key, per CyberSource JWT shared-secret guidance.
        $rawSecret = $merchantConfig->getSecretKey();
        if (empty($rawSecret)) {
            self::$logger->error("AuthException: " . GlobalParameter::JWT_SHARED_SECRET_KEY_REQ);
            throw new AuthException("AuthException: " . GlobalParameter::JWT_SHARED_SECRET_KEY_REQ);
        }

        $decodedSecret = base64_decode($rawSecret, true);
        if ($decodedSecret === false) {
            self::$logger->error(GlobalParameter::JWT_SHARED_SECRET_DECODE_FAIL);
            throw new AuthException(GlobalParameter::JWT_SHARED_SECRET_DECODE_FAIL);
        }

        return JWT::encode($jwtPayload, $decodedSecret, $algorithm, $kid, $headerClaimSet);
    }

    private function getPayloadClaimSet($resourcePath, $payloadData, $method, $merchantConfig, $isResponseMLEForAPI)
    {
        $jwtPayload = array();

        // Setting the JWT digest and digest Algorithm when a POST, PUT, or PATCH request is made
        if($method == GlobalParameter::POST || $method == GlobalParameter::PUT || $method == GlobalParameter::PATCH)
        {
            $digestObj = new PayloadDigest($merchantConfig->getLogConfiguration());
            $digest = $digestObj->generateDigest($payloadData);
            $jwtPayload["digest"] = $digest;
            $jwtPayload["digestAlgorithm"] = "SHA-256";
        }

        // Set the iat and exp claims using Unix timestamps
        $currentTime = time();
        $jwtPayload["iat"] = $currentTime;
        $jwtPayload["exp"] = $currentTime + 120; // The exp claim is set to 2 mins more than the iat claim

        // Set the request method, host and resource path in the JWT body as per the specification for all request types
        $jwtPayload["request-method"] = strtoupper($method);
        $jwtPayload["request-host"] = $merchantConfig->getRunEnvironment();
        $jwtPayload["request-resource-path"] = $this->extractResourcePath($resourcePath);

        // Choose issuer claim in the JWT body as per the use_metakey flag in the config file
        if($merchantConfig->getUseMetaKey())
        {
            $issuer = $merchantConfig->getPortfolioID();
        }
        else
        {
            $issuer = $merchantConfig->getMerchantID();
        }

        $jwtPayload["iss"] = $issuer;
        $uuid = Uuid::uuid4();
        $jwtPayload["jti"] = $uuid->toString(); // Unique JWT ID
        $jwtPayload["v-c-jwt-version"] = "2";
        $jwtPayload["v-c-merchant-id"] = $merchantConfig->getMerchantID();

        if (!empty($isResponseMLEForAPI)) {
            $jwtPayload['v-c-response-mle-kid'] = MLEUtility::validateAndAutoExtractResponseMleKid($merchantConfig);
        }

        return $jwtPayload;
    }

    private function getHeaderClaimSet()
    {
        // To add any future parameters to the header claim set, add them to this array and it can be returned
        $jwtHeaders = array(
        );

        return $jwtHeaders;
    }

    private function extractSerialNumber($x509Certificate)
    {
        try {
            $certDetails = openssl_x509_parse($x509Certificate);

            if (isset($certDetails['subject']['serialNumber'])) {
                return $certDetails['subject']['serialNumber'];
            }

            $errorMsg = "Serial number not found in certificate subject field.";
            self::$logger->error($errorMsg);
            throw new AuthException($errorMsg);

        } catch(AuthException $e) {
            throw $e; // Re-throw AuthException without wrapping
        }   
        catch (\Exception $e) {
            self::$logger->error("Error extracting serial number from certificate: " . $e->getMessage());
            throw new AuthException("Error extracting serial number from certificate: " . $e->getMessage());
        }
    }

    private function extractResourcePath($resourcePath)
    {
        if (empty($resourcePath)) {
            return "";
        }

        // Split the string to remove the query params
        $parts = explode('?', $resourcePath, 2);
        return $parts[0];
    }

}
?>
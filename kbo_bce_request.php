<?php

    $client = new SoapClient('https://kbopub-acc.economie.fgov.be/kbopubws050000/services/wsKBOPub?wsdl');
	
	$message_id = 'a_message_identifier';
	$language = 'nl'; // or 'fr'
	$KBO_BCE_number="0123456789";
	
    $soapHeader[0] = soapClientWSSecurityHeader('USERID', 'PASSWORD');
    $soapHeader[1] = soapClientContextHeader($message_id, $language);
    $client->__setSoapHeaders($soapHeader);

    try {
        $response = $client->ReadEnterprise(['EnterpriseNumber' => $KBO_BCE_number]);
    } catch (SoapFault $fault) {
        echo "ERROR: ".$fault->faultcode."-".$fault->faultstring;
    }

    var_dump($response);

  /**
    * This function implements a WS-Security digest authentification.
    *
    * @access private
    * @param string $user
    * @param string $password
    * @return SoapHeader
    */
   function soapClientWSSecurityHeader($user, $password)
   {
      // Creating date using yyyy-mm-ddThh:mm:ssZ format
      $tm_created = gmdate('Y-m-d\TH:i:s\Z');
      $tm_expires = gmdate('Y-m-d\TH:i:s\Z', gmdate('U') + 180); //only necessary if using the timestamp element

      // Generating and encoding a random number
      $simple_nonce = mt_rand();
      $encoded_nonce = base64_encode($simple_nonce);

      // Compiling WSS string
      $passdigest = base64_encode(sha1($simple_nonce . $tm_created . $password, true));

      // Initializing namespaces
      $ns_wsse = 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd';
      $ns_wsu = 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd';
      $password_type = 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordDigest';
      $encoding_type = 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary';

      // Creating WSS identification header using SimpleXML
      $root = new SimpleXMLElement('<root/>');

      $security = $root->addChild('wsse:Security', null, $ns_wsse);

      //the timestamp element is not required by all servers
      $timestamp = $security->addChild('wsu:Timestamp', null, $ns_wsu);
      $timestamp->addAttribute('wsu:Id', 'Timestamp-28');
      $timestamp->addChild('wsu:Created', $tm_created, $ns_wsu);
      $timestamp->addChild('wsu:Expires', $tm_expires, $ns_wsu);

      $usernameToken = $security->addChild('wsse:UsernameToken', null, $ns_wsse);
      $usernameToken->addChild('wsse:Username', $user, $ns_wsse);
      $usernameToken->addChild('wsse:Password', $passdigest, $ns_wsse)->addAttribute('Type', $password_type);
      $usernameToken->addChild('wsse:Nonce', $encoded_nonce, $ns_wsse)->addAttribute('EncodingType', $encoding_type);
      $usernameToken->addChild('wsu:Created', $tm_created, $ns_wsu);

      // Recovering XML value from that object
      $x = $root->registerXPathNamespace('wsse', $ns_wsse);

      $full = $root->xpath('/root/wsse:Security');

      $auth = $full[0]->asXML();
      //var_dump($auth); die();

      return new SoapHeader($ns_wsse, 'Security', new SoapVar($auth, XSD_ANYXML), true);
   }

	/**
    * This function implements a RequestContext soapheader.
    *
    * @access private
    * @param string $id
    * @param string $language
    * @return SoapHeader
    */
   function soapClientContextHeader($id, $language)
   {
      // Initializing namespace
      $ns_mes = "http://economie.fgov.be/kbopub/webservices/v1/messages";

      $root = new SimpleXMLElement('<root/>');

      $message = $root->addChild('mes:RequestContext', null, $ns_mes);
      $message->addChild('mes:Id', $id, $ns_mes);
      $messsage->addChild('mes:Language', $language, $ns_mes);

      $x = $root->registerXPathNamespace('mes', $ns_mes);
      $full = $root->xpath('/root/mes:RequestContext');
      $auth = $full[0]->asXML();

      return new SoapHeader($ns_mes, 'RequestContext', new SoapVar($auth, XSD_ANYXML), true);
   }
   
   

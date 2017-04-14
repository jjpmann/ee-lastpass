<?php

function lp_saml_auth($settings, $resp)
{
    $saml_cert = trim($settings['cert']);

    if (empty($saml_cert)) {
        print "LastPass has detected that you have no SAML certificate setup in settings -- aborting.";
        return false;
    }

    $entity_id = lastpass_get_entity_id();
    // $acs = get_site_url();
    $acs = 'http://ee-3.5.3/lastpass_login';

    //echo "<pre>".__FILE__.'<br>'.__METHOD__.' : '.__LINE__."<br><br>"; var_dump( $resp, $saml_cert, $acs, $entity_id ); exit;
    

    $samlresponse = new LP_saml_response($resp, $saml_cert, $acs, $entity_id);
    
    // echo "<pre>".__FILE__.'<br>'.__METHOD__.' : '.__LINE__."<br><br>"; var_dump( $samlresponse ); exit;
    

    // all parsed dates are in UTC
    $cur_tz = date_default_timezone_get();
    date_default_timezone_set('UTC');

    try {
        $resp_ok = $samlresponse->validate();
    } catch (Exception $e) {
        error_log("Exception processing SAML response: " . $e->getMessage());
        $resp_ok = false;
    }

    date_default_timezone_set($cur_tz);

    if ($resp_ok) {
        $name = $samlresponse->get_email();
        return $name;
    } else {
        print "Invalid SAMLResponse -- aborting.";
        return "";
    }
}

function of($s)
{
    $s2 = @htmlentities($s, ENT_QUOTES, "UTF-8");
    if (is_null($s2)) {
        $s2 = "";
    }
    return $s2;
}

function ofa($s)
{
    $s2 = @htmlentities($s, ENT_QUOTES, "UTF-8");
    if (is_null($s2)) {
        L("ERROR: htmlentities passed invalid string s=$s");
        $s2 = "";
    }
    //$g_timeinofa += (microtime(true)-$timestart);
    return $s2;
}

function ofx($s)
{
    $s = preg_replace("/[\x01-\x08]|\x0B|\x0C|[\x0E-\x1F]/","",$s);
    return str_replace("'","&apos;",htmlspecialchars($s,ENT_COMPAT,"UTF-8"));
}

function lastpass_get_entity_id()
{
    if (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] != 'off') {
        return "LastPass:ExpressioneEngine:https://".str_replace("www.", "", $_SERVER['HTTP_HOST']);
    } else {
        return "LastPass:ExpressioneEngine:http://".str_replace("www.", "", $_SERVER['HTTP_HOST']);
    }
}

function lp_AuthnRequest($settings)
{
    $issuer = lastpass_get_entity_id();

    $randstr = bin2hex(openssl_random_pseudo_bytes(32));
    $id = "samlr-" . $randstr;
    $issue_instant = gmdate("Y-m-d\TH:i:s\Z");

    $url = 'http://ee-3.5.3/lastpass_login';

    $req =  '<?xml version="1.0"?>
       <samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="' . ofx($id) . '" IssueInstant="' . ofx($issue_instant) . '" Version="2.0" AssertionConsumerServiceURL="'.ofx($url).'"><saml:Issuer>'.ofx($issuer).'</saml:Issuer><samlp:NameIDPolicy AllowCreate="true" Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"/></samlp:AuthnRequest>';

    $samlrequest = urlencode(base64_encode(gzdeflate($req)));
    $relaystate = urlencode($url ."/");
    $login_url = $settings['login'];
    header("Location: $login_url?SAMLRequest=$samlrequest&RelayState=$relaystate");
    die('ok');
}

class LP_saml_response
{
    private $xml,$xpath,$saml_cert;

    function __construct($b64Str, $cert, $acs, $entity_id)
    {
        $xmlStr = base64_decode($b64Str);

        //die($xmlStr);

        $this->xml = new DOMDocument();
        $this->xml->loadXML($xmlStr);
        $this->saml_cert  = $cert;
        $this->acs = $acs;
        $this->entity_id = $entity_id;
    }

    function get_email()
    {
        $xpath = new DOMXPath($this->xml);
        $q = "/samlp:Response/saml:Assertion/saml:Subject/saml:NameID";
        $ent = $xpath->query($q);
        return $ent->item(0)->nodeValue;
    }

    function validateSig($node)
    {

        // Mostly from xmlseclibs test examples.
        $objXMLSecDSig = new XMLSecurityDSig();

        $objDSig = $objXMLSecDSig->locateSignature($node);

        if (!$objDSig) {
            throw new Exception("Cannot locate Signature Node");
        }
        $objXMLSecDSig->canonicalizeSignedinfo();
        $objXMLSecDSig->idKeys = array('ID');

        $retVal = $objXMLSecDSig->validateReference();

        if (!$retVal) {
            throw new Exception("Reference Validation Failed");
        }

        $objKey = $objXMLSecDSig->locateKey();


        if (!$objKey ) {
            throw new Exception("We have no idea about the key");
        }
        $key = NULL;

        $objKeyInfo = XMLSecEnc::staticLocateKeyinfo($objKey, $objDSig);
        $objKey->loadKey($this->saml_cert, FALSE, TRUE);
        return $objXMLSecDSig->verify($objKey);
    }

    function validate()
    {
        $acs = $this->acs;
        $entity_id = $this->entity_id;

        // allow this much slack
        $slack = 5 * 60;

        // signature must match our SP's signature.
        if (!$this->validateSig($this->xml))
            throw new Exception("Invalid signature");

        // response must be successful
        $xpath = new DOMXPath($this->xml);
        $q = "string(/samlp:Response/samlp:Status/samlp:StatusCode/@Value)";
        $attr = $xpath->evaluate($q);
        if ("urn:oasis:names:tc:SAML:2.0:status:Success" !== $attr) {
            throw new Exception("Invalid response status");
        }

        // response destination must match ACS
        // LastPass automatically-generated ACS may have an extra slash,
        // so allow that as well.
        $q = "string(/samlp:Response/@Destination)";
        $attr = $xpath->evaluate($q);
        if ($acs !== $attr && $acs . '/' !== $attr) {
            throw new Exception("Invalid destination");
        }

        $now = time();

        // issue instant must be within a day
        $q = "string(/samlp:Response/@IssueInstant)";
        $attr = $xpath->evaluate($q);
        if (!$attr)
            throw new Exception("Missing issue instant");
        $then = strtotime($attr);

        if (abs($then - $now) > 86400 + $slack) {
            throw new Exception("Invalid issue instant");
        }

        // only support a single assertion, single subject, require conf data.
        $q = "/samlp:Response/saml:Assertion";
        $assertions = $xpath->query($q);
        if ($assertions->length != 1)
            throw new Exception("Incorrect number of assertions");

        $q = "/samlp:Response/saml:Assertion/saml:Subject";
        $subjects = $xpath->query($q);
        if ($subjects->length != 1)
            throw new Exception("Incorrect number of subjects");

        $q = "/samlp:Response/saml:Assertion/saml:Subject/saml:SubjectConfirmation/saml:SubjectConfirmationData";
        $subject_conf_datas = $xpath->query($q);
        if ($subject_conf_datas->length != 1)
            throw new Exception("Incorrect number of subject confirmations");

        $assertion = $assertions->item(0);
        $subject = $subjects->item(0);
        $subject_conf_data = $subject_conf_datas->item(0);

        // Assertion must be signed correctly
        if (!$this->validateSig($assertion))
            throw new Exception("Invalid assertion signature");

        // Assertion must contain an authnstatement with an unexpired session
        $q = "saml:AuthnStatement";
        $stmts = $xpath->query($q, $assertion);
        foreach ($stmts as $stmt) {
            $attr = $xpath->evaluate("string(@SessionNotOnOrAfter)", $stmt);
            if (!$attr)
                throw new Exception("Missing authn SessionNotOnOrAfter");
            $then = strtotime($attr) + $slack;
            if ($now >= $then)
                throw new Exception("Invalid authn SessionNotOnOrAfter");
        }

        // Assertion IssueInstant must be within a day
        $instant = $xpath->evaluate("string(@IssueInstant)", $assertion);
        if (!$instant)
            throw new Exception("Missing assertion IssueInstant");
        $then = strtotime($instant);
        if (abs($then - $now) > 86400 + $slack) {
            throw new Exception("Invalid assertion IssueInstant");
        }

        // Assertion conditions met
        $mintime = $xpath->evaluate("string(saml:Conditions/@NotBefore)", $assertion);
        $maxtime = $xpath->evaluate("string(saml:Conditions/@NotOnOrAfter)", $assertion);
        if (!$mintime || !$maxtime)
            throw new Exception("Missing conditions limits");

        $mintime = strtotime($mintime);
        $maxtime = strtotime($maxtime);

        $mintime -= $slack;
        $maxtime += $slack;
        if ($now < $mintime || $now >= $maxtime)
            throw new Exception("Invalid conditions limits");

        // Audience matches entity id
        $ar = $xpath->evaluate("string(saml:Conditions/saml:AudienceRestriction/saml:Audience)", $assertion);
        if ($entity_id !== $ar)
            throw new Exception("Invalid audience");

        // SubjectConfirmationData must have a recipient that matches ACS,
        // with a valid NotOnOrAfter
        $recipient = $xpath->evaluate("string(@Recipient)", $subject_conf_data);
        if ($acs !== $recipient && $acs . '/' !== $recipient)
            throw new Exception("Invalid subject conf recipient");

        $attr = $xpath->evaluate("string(@NotOnOrAfter)", $subject_conf_data);
        $then = strtotime($attr) + $slack;
        if ($now >= $then)
            throw new Exception("Invalid subject conf NotOnOrAfter");

        return TRUE;
    }
}

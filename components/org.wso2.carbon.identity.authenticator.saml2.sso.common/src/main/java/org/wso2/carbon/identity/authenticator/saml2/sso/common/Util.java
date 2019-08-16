/*
 * Copyright (c) 2005, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.wso2.carbon.identity.authenticator.saml2.sso.common;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.xerces.impl.Constants;
import org.apache.xml.security.c14n.Canonicalizer;
import org.opensaml.Configuration;
import org.opensaml.DefaultBootstrap;
import org.opensaml.common.impl.SecureRandomIdentifierGenerator;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.Attribute;
import org.opensaml.saml2.core.AttributeStatement;
import org.opensaml.saml2.core.AuthnRequest;
import org.opensaml.saml2.core.EncryptedAssertion;
import org.opensaml.saml2.core.LogoutRequest;
import org.opensaml.saml2.core.Response;
import org.opensaml.saml2.encryption.Decrypter;
import org.opensaml.xml.ConfigurationException;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.XMLObjectBuilder;
import org.opensaml.xml.encryption.DecryptionException;
import org.opensaml.xml.encryption.EncryptedKey;
import org.opensaml.xml.io.Marshaller;
import org.opensaml.xml.io.MarshallerFactory;
import org.opensaml.xml.io.Unmarshaller;
import org.opensaml.xml.io.UnmarshallerFactory;
import org.opensaml.xml.security.SecurityHelper;
import org.opensaml.xml.security.credential.Credential;
import org.opensaml.xml.security.keyinfo.KeyInfoCredentialResolver;
import org.opensaml.xml.security.keyinfo.StaticKeyInfoCredentialResolver;
import org.opensaml.xml.security.x509.X509Credential;
import org.opensaml.xml.signature.KeyInfo;
import org.opensaml.xml.signature.Signature;
import org.opensaml.xml.signature.Signer;
import org.opensaml.xml.signature.X509Certificate;
import org.opensaml.xml.signature.X509Data;
import org.opensaml.xml.util.Base64;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;
import org.w3c.dom.bootstrap.DOMImplementationRegistry;
import org.w3c.dom.ls.DOMImplementationLS;
import org.w3c.dom.ls.LSOutput;
import org.w3c.dom.ls.LSSerializer;
import org.wso2.carbon.core.security.AuthenticatorsConfiguration;
import org.wso2.carbon.core.util.KeyStoreManager;
import org.wso2.carbon.identity.authenticator.saml2.sso.common.builders.SignKeyDataHolder;
import org.wso2.carbon.identity.authenticator.saml2.sso.common.internal.SAML2SSOAuthFEDataHolder;
import org.wso2.carbon.identity.authenticator.saml2.sso.common.util.CarbonEntityResolver;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.utils.multitenancy.MultitenantConstants;
import org.xml.sax.SAXException;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.Key;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Random;
import java.util.concurrent.ConcurrentHashMap;
import javax.crypto.SecretKey;
import javax.xml.namespace.QName;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

/**
 * This class contains all the utility methods required by SAML2 SSO Authenticator module.
 */
public class Util {
    private  Util(){

    }

    private static final char[] charMapping = {'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j',
            'k', 'l', 'm', 'n', 'o', 'p'};
    private static boolean bootStrapped = false;
    private static final Log log = LogFactory.getLog(Util.class);
    private static Random random = new Random();
    private static String serviceProviderId = null;
    private static String identityProviderSSOServiceURL = null;
    private static Map<String, String> parameters = new HashMap<String, String>();
    private static String identityProviderSLOServiceURL = parameters.get(
            SAML2SSOAuthenticatorConstants.IDENTITY_PROVIDER_SLO_SERVICE_URL);
    private static String loginPage = "/carbon/admin/login.jsp";
    private static String landingPage = null;
    private static String externalLogoutPage = null;
    private static boolean logoutSupportedIDP = false;
    private static String assertionConsumerServiceUrl = null;
    private static boolean initSuccess = false;
    private static Properties saml2IdpProperties = new Properties();
    private static Map<String, String> cachedIdps = new ConcurrentHashMap<String, String>();

    /**
     * Constructing the XMLObject Object from a String
     *
     * @param authReqStr
     * @return Corresponding XMLObject which is a SAML2 object
     * @throws SAML2SSOUIAuthenticatorException
     */
    public static XMLObject unmarshall(String authReqStr) throws SAML2SSOUIAuthenticatorException {

        try {
            doBootstrap();
            DocumentBuilderFactory documentBuilderFactory = IdentityUtil.getSecuredDocumentBuilderFactory();
            Document document = getDocument(documentBuilderFactory, authReqStr);
            if (isSignedWithComments(document)) {
                documentBuilderFactory.setIgnoringComments(false);
                document = getDocument(documentBuilderFactory, authReqStr);
            }
            Element element = document.getDocumentElement();
            UnmarshallerFactory unmarshallerFactory = Configuration.getUnmarshallerFactory();
            Unmarshaller unmarshaller = unmarshallerFactory.getUnmarshaller(element);
            return unmarshaller.unmarshall(element);
        } catch (Exception e) {
            log.error("Error in constructing AuthRequest from the encoded String", e);
            throw new SAML2SSOUIAuthenticatorException("Error in constructing AuthRequest from "
                    + "the encoded String ", e);
        }
    }

    /**
     * Return whether SAML Assertion has the canonicalization method
     * set to 'http://www.w3.org/2001/10/xml-exc-c14n#WithComments'.
     *
     * @param document
     * @return true if canonicalization method equals to 'http://www.w3.org/2001/10/xml-exc-c14n#WithComments'
     */
    private static boolean isSignedWithComments(Document document) {

        XPath xPath = XPathFactory.newInstance().newXPath();
        try {
            String assertionId = (String) xPath.compile("//*[local-name()='Assertion']/@ID")
                    .evaluate(document, XPathConstants.STRING);

            if (StringUtils.isBlank(assertionId)) {
                return false;
            }

            NodeList nodeList = ((NodeList) xPath.compile(
                    "//*[local-name()='Assertion']" +
                            "/*[local-name()='Signature']" +
                            "/*[local-name()='SignedInfo']" +
                            "/*[local-name()='Reference'][@URI='#" + assertionId + "']" +
                            "/*[local-name()='Transforms']" +
                            "/*[local-name()='Transform']" +
                            "[@Algorithm='http://www.w3.org/2001/10/xml-exc-c14n#WithComments']")
                    .evaluate(document, XPathConstants.NODESET));
            return nodeList != null && nodeList.getLength() > 0;
        } catch (XPathExpressionException e) {
            String message = "Failed to find the canonicalization algorithm of the assertion. Defaulting to: " +
                    "http://www.w3.org/2001/10/xml-exc-c14n#";
            log.warn(message);
            if (log.isDebugEnabled()) {
                log.debug(message, e);
            }
            return false;
        }
    }

    private static Document getDocument(DocumentBuilderFactory documentBuilderFactory, String samlString)
            throws IOException, SAXException, ParserConfigurationException {

        DocumentBuilder docBuilder = documentBuilderFactory.newDocumentBuilder();
        docBuilder.setEntityResolver(new CarbonEntityResolver());
        return docBuilder.parse(new ByteArrayInputStream(samlString.trim().getBytes()));
    }

    /**
     * Serializing a SAML2 object into a String
     *
     * @param xmlObject object that needs to serialized.
     * @return serialized object
     * @throws SAML2SSOUIAuthenticatorException
     */
    public static String marshall(XMLObject xmlObject) throws SAML2SSOUIAuthenticatorException {

        try {
            doBootstrap();
            System.setProperty("javax.xml.parsers.DocumentBuilderFactory",
                    "org.apache.xerces.jaxp.DocumentBuilderFactoryImpl");

            MarshallerFactory marshallerFactory = org.opensaml.xml.Configuration
                    .getMarshallerFactory();
            Marshaller marshaller = marshallerFactory.getMarshaller(xmlObject);
            Element element = marshaller.marshall(xmlObject);

            ByteArrayOutputStream byteArrayOutputStrm = new ByteArrayOutputStream();
            DOMImplementationRegistry registry = DOMImplementationRegistry.newInstance();
            DOMImplementationLS impl = (DOMImplementationLS) registry.getDOMImplementation("LS");
            LSSerializer writer = impl.createLSSerializer();
            LSOutput output = impl.createLSOutput();
            output.setByteStream(byteArrayOutputStrm);
            writer.write(element, output);
            return byteArrayOutputStrm.toString();
        } catch (Exception e) {
            log.error("Error Serializing the SAML Response");
            throw new SAML2SSOUIAuthenticatorException("Error Serializing the SAML Response", e);
        }
    }

    /**
     * Encoding the response
     *
     * @param xmlString String to be encoded
     * @return encoded String
     */
    public static String encode(String xmlString) throws Exception {

        String encodedRequestMessage = Base64.encodeBytes(xmlString.getBytes(), Base64.DONT_BREAK_LINES);
        return encodedRequestMessage.trim();
    }

    /**
     * Decoding and deflating the encoded AuthReq
     *
     * @param encodedStr encoded AuthReq
     * @return decoded AuthReq
     */
    public static String decode(String encodedStr) throws SAML2SSOUIAuthenticatorException {

        try {
            org.apache.commons.codec.binary.Base64 base64Decoder = new org.apache.commons.codec.binary.Base64();
            byte[] xmlBytes = encodedStr.getBytes("UTF-8");
            byte[] base64DecodedByteArray = base64Decoder.decode(xmlBytes);

            return new String(base64DecodedByteArray, 0, base64DecodedByteArray.length, "UTF-8");

        } catch (IOException e) {
            throw new SAML2SSOUIAuthenticatorException("Error when decoding the SAML Request.", e);
        }

    }

    /**
     * This method is used to initialize the OpenSAML2 library. It calls the bootstrap method, if it
     * is not initialized yet.
     */
    public static void doBootstrap() {
        if (!bootStrapped) {
            try {
                DefaultBootstrap.bootstrap();
                bootStrapped = true;
            } catch (ConfigurationException e) {
                log.error("Error in bootstrapping the OpenSAML2 library", e);
            }
        }
    }

    public static AuthnRequest setSignature(AuthnRequest authnRequest, String signatureAlgorithm,
                                            X509Credential cred) throws Exception {

        if (log.isDebugEnabled()) {
            log.debug("Signing the AuthnRequest");
        }
        doBootstrap();
        try {
            Signature signature = (Signature) buildXMLObject(Signature.DEFAULT_ELEMENT_NAME);
            signature.setSigningCredential(cred);
            signature.setSignatureAlgorithm(signatureAlgorithm);
            signature.setCanonicalizationAlgorithm(Canonicalizer.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);

            try {
                KeyInfo keyInfo = (KeyInfo) buildXMLObject(KeyInfo.DEFAULT_ELEMENT_NAME);
                X509Data data = (X509Data) buildXMLObject(X509Data.DEFAULT_ELEMENT_NAME);
                X509Certificate cert = (X509Certificate) buildXMLObject(X509Certificate.DEFAULT_ELEMENT_NAME);
                String value = org.apache.xml.security.utils.Base64.encode(cred
                        .getEntityCertificate().getEncoded());
                cert.setValue(value);
                data.getX509Certificates().add(cert);
                keyInfo.getX509Datas().add(data);
                signature.setKeyInfo(keyInfo);
            } catch (CertificateEncodingException e) {
                throw new SAML2SSOUIAuthenticatorException("errorGettingCert ",e);
            }

            authnRequest.setSignature(signature);

            List<Signature> signatureList = new ArrayList<Signature>();
            signatureList.add(signature);

            // Marshall and Sign
            MarshallerFactory marshallerFactory = org.opensaml.xml.Configuration
                    .getMarshallerFactory();
            Marshaller marshaller = marshallerFactory.getMarshaller(authnRequest);

            marshaller.marshall(authnRequest);

            org.apache.xml.security.Init.init();
            Signer.signObjects(signatureList);
            return authnRequest;

        } catch (Exception e) {
            throw new Exception("Error While signing the assertion.", e);
        }
    }

    public static LogoutRequest setSignature(LogoutRequest logoutReq, String signatureAlgorithm,
                                             SignKeyDataHolder cred) throws Exception {

        if (log.isDebugEnabled()) {
            log.debug("Signing the AuthnRequest");
        }
        doBootstrap();
        try {
            Signature signature = (Signature) buildXMLObject(Signature.DEFAULT_ELEMENT_NAME);
            signature.setSigningCredential(cred);
            signature.setSignatureAlgorithm(signatureAlgorithm);
            signature.setCanonicalizationAlgorithm(Canonicalizer.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);

            try {
                KeyInfo keyInfo = (KeyInfo) buildXMLObject(KeyInfo.DEFAULT_ELEMENT_NAME);
                X509Data data = (X509Data) buildXMLObject(X509Data.DEFAULT_ELEMENT_NAME);
                X509Certificate cert = (X509Certificate) buildXMLObject(X509Certificate.DEFAULT_ELEMENT_NAME);
                String value = org.apache.xml.security.utils.Base64.encode(cred
                        .getEntityCertificate().getEncoded());
                cert.setValue(value);
                data.getX509Certificates().add(cert);
                keyInfo.getX509Datas().add(data);
                signature.setKeyInfo(keyInfo);
            } catch (CertificateEncodingException e) {
                throw new Exception("errorGettingCert ",e);
            }

            logoutReq.setSignature(signature);

            List<Signature> signatureList = new ArrayList<Signature>();
            signatureList.add(signature);

            // Marshall and Sign
            MarshallerFactory marshallerFactory = org.opensaml.xml.Configuration
                    .getMarshallerFactory();
            Marshaller marshaller = marshallerFactory.getMarshaller(logoutReq);

            marshaller.marshall(logoutReq);

            org.apache.xml.security.Init.init();
            Signer.signObjects(signatureList);
            return logoutReq;

        } catch (Exception e) {
            throw new Exception("Error While signing the assertion.", e);
        }
    }

    public static XMLObject buildXMLObject(QName objectQName) throws Exception {

        XMLObjectBuilder builder = org.opensaml.xml.Configuration.getBuilderFactory().getBuilder(
                objectQName);
        if (builder == null) {
            throw new Exception("Unable to retrieve builder for object QName " + objectQName);
        }
        return builder.buildObject(objectQName.getNamespaceURI(), objectQName.getLocalPart(),
                objectQName.getPrefix());
    }

    /**
     * Generates a unique Id for Authentication Requests
     *
     * @return generated unique ID
     */
    public static String createID() throws Exception {

        try {
            SecureRandomIdentifierGenerator generator = new SecureRandomIdentifierGenerator();
            return generator.generateIdentifier();
        } catch (NoSuchAlgorithmException e) {
            throw new Exception("Error while building Secure Random ID.", e);
        }
    }

    /**
     * Sets the issuerID and IDP SSO Service URL during the server start-up by reading
     * authenticators.xml
     */
    public static boolean initSSOConfigParams() {

        AuthenticatorsConfiguration authenticatorsConfiguration = AuthenticatorsConfiguration
                .getInstance();
        AuthenticatorsConfiguration.AuthenticatorConfig authenticatorConfig = authenticatorsConfiguration
                .getAuthenticatorConfig(SAML2SSOAuthenticatorConstants.AUTHENTICATOR_NAME);
        if (authenticatorConfig != null) {
            parameters = authenticatorConfig.getParameters();
            serviceProviderId = parameters.get(SAML2SSOAuthenticatorConstants.SERVICE_PROVIDER_ID);
            identityProviderSSOServiceURL = parameters
                    .get(SAML2SSOAuthenticatorConstants.IDENTITY_PROVIDER_SSO_SERVICE_URL);
            identityProviderSLOServiceURL = parameters
                    .get(SAML2SSOAuthenticatorConstants.IDENTITY_PROVIDER_SLO_SERVICE_URL);
            loginPage = parameters.get(SAML2SSOAuthenticatorConstants.LOGIN_PAGE);
            landingPage = parameters.get(SAML2SSOAuthenticatorConstants.LANDING_PAGE);
            externalLogoutPage = parameters.get(SAML2SSOAuthenticatorConstants.EXTERNAL_LOGOUT_PAGE);
            logoutSupportedIDP = Boolean.parseBoolean(parameters.get(SAML2SSOAuthenticatorConstants.LOGOUT_SUPPORTED_IDP));
            assertionConsumerServiceUrl = parameters.get(SAML2SSOAuthenticatorConstants.ASSERTION_CONSUMER_SERVICE_URL);

            initSuccess = true;
        }
        return initSuccess;
    }

    /**
     * checks whether authenticator enable ot disable
     *
     * @return True/False
     */
    public static boolean isAuthenticatorEnabled() {

        AuthenticatorsConfiguration authenticatorsConfiguration = AuthenticatorsConfiguration
                .getInstance();
        AuthenticatorsConfiguration.AuthenticatorConfig authenticatorConfig = authenticatorsConfiguration
                .getAuthenticatorConfig(SAML2SSOAuthenticatorConstants.AUTHENTICATOR_NAME);
        // if the authenticator is disabled, then do not register the servlet filter.
        return !authenticatorConfig.isDisabled();
    }

    /**
     * returns the service provider ID of a particular server
     *
     * @return service provider ID
     */
    public static String getServiceProviderId() {

        if (!initSuccess) {
            initSSOConfigParams();
        }
        return serviceProviderId;
    }

    /**
     * returns the Identity Provider SSO Service URL
     *
     * @return dentity Provider SSO Service URL
     */
    public static String getIdentityProviderSSOServiceURL() {

        if (!initSuccess) {
            initSSOConfigParams();
        }
        return identityProviderSSOServiceURL;
    }

    /**
     * returns the Identity Provider SSO Service URL
     *
     * @return dentity Provider SSO Service URL
     */
    public static String getIdentityProviderSLOServiceURL() {

        if (!initSuccess) {
            initSSOConfigParams();
        }
        return identityProviderSLOServiceURL;
    }

    /**
     * returns the Assertion Consumer Service URL
     *
     * @return Assertion Consumer Service URL
     */
    public static String getAssertionConsumerServiceURL() {

        if (!initSuccess) {
            initSSOConfigParams();
        }
        return assertionConsumerServiceUrl;
    }

    /**
     * @param federatedDomain
     * @return
     */
    public static String getIdentityProviderSSOServiceURL(String federatedDomain) {

        if (!initSuccess) {
            initSSOConfigParams();
        }

        String fedeartedIdp = null;

        if (federatedDomain == null) {
            return null;
        }

        String selfDomain = parameters.get("IdpSelfDomain");
        federatedDomain = federatedDomain.trim().toUpperCase();

        if (selfDomain != null && selfDomain.trim().toUpperCase().equals(federatedDomain)) {
            return null;
        }

        fedeartedIdp = cachedIdps.get(federatedDomain);

        if (fedeartedIdp == null) {
            fedeartedIdp = saml2IdpProperties.getProperty(federatedDomain);
        }

        if (log.isDebugEnabled()) {
            log.debug("Federated domain : " + fedeartedIdp);
        }

        if (fedeartedIdp != null) {
            cachedIdps.put(federatedDomain, fedeartedIdp);
        }

        return fedeartedIdp;
    }

    /**
     * Gets the login page URL that needs to be filtered.
     *
     * @return login page URL.
     */
    public static String getLoginPage() {
        return loginPage;
    }

    /**
     * Returns the landing page to which the login requests will be redirected to.
     *
     * @return URL of the landing page
     */
    public static String getLandingPage() {
        return landingPage;
    }

    /**
     * Returns the external logout page url, to which user-agent is redirected
     * after invalidating the local carbon session
     *
     * @return
     */
    public static String getExternalLogoutPage() {
        return externalLogoutPage;
    }

    /**
     * Returns whether IDP supported for logout or not
     * used while redirecting to external logout page
     * @return
     */
    public static boolean isLogoutSupportedIDP() {
        return logoutSupportedIDP;
    }

    /**
     * Returns the login attribute name which use to get the username from the SAML2 Response.
     *
     * @return Name of the login attribute
     */
    public static String getLoginAttributeName() {

        if (!initSuccess) {
            initSSOConfigParams();
        }
        return parameters.get(SAML2SSOAuthenticatorConstants.LOGIN_ATTRIBUTE_NAME);
    }

    /**
     * Get the username from the SAML2 XMLObject
     *
     * @param xmlObject SAML2 XMLObject
     * @return username
     */
    public static String getUsername(XMLObject xmlObject) {

        if (xmlObject instanceof Response) {
            return getUsernameFromResponse((Response) xmlObject);
        } else if (xmlObject instanceof Assertion) {
            return getUsernameFromAssertion((Assertion) xmlObject);
        } else {
            return null;
        }
    }

    /**
     * Get the username from the SAML2 Response
     *
     * @param response SAML2 Response
     * @return username username contained in the SAML Response
     */
    public static String getUsernameFromResponse(Response response) {

        List<Assertion> assertions = response.getAssertions();
        Assertion assertion = null;
        if (assertions != null && assertions.size() > 0) {
            // There can be only one assertion in a SAML Response, so get the
            // first one
            assertion = assertions.get(0);
            return getUsernameFromAssertion(assertion);

        } else {
            List<EncryptedAssertion> encryptedAssertions = response.getEncryptedAssertions();
            EncryptedAssertion encryptedAssertion;
            if (encryptedAssertions.size() > 0) {
                encryptedAssertion = encryptedAssertions.get(0);
                String tenantDomain = MultitenantConstants.SUPER_TENANT_DOMAIN_NAME;
                try {
                    assertion = getDecryptedAssertion(encryptedAssertion, tenantDomain);
                } catch (SAML2SSOUIAuthenticatorException e) {
                    log.error("Error while obtaining user name from response.");
                }
                return getUsernameFromAssertion(assertion);
            }
        }
        return null;
    }

    /**
     * Get the username from the SAML2 Assertion
     *
     * @param assertion SAML2 assertion
     * @return username
     */
    public static String getUsernameFromAssertion(Assertion assertion) {

        String loginAttributeName = getLoginAttributeName();

        if (loginAttributeName != null) {
            // There can be multiple AttributeStatements in Assertion
            List<AttributeStatement> attributeStatements = assertion
                    .getAttributeStatements();
            if (attributeStatements != null) {
                for (AttributeStatement attributeStatement : attributeStatements) {
                    // There can be multiple Attributes in a
                    // attributeStatement
                    List<Attribute> attributes = attributeStatement
                            .getAttributes();
                    if (attributes != null) {
                        for (Attribute attribute : attributes) {
                            String attributeName = attribute.getDOM()
                                    .getAttribute("Name");
                            if (attributeName.equals(loginAttributeName)) {
                                List<XMLObject> attributeValues = attribute
                                        .getAttributeValues();
                                // There can be multiple attribute values in
                                // a attribute, but get the first one
                                return attributeValues.get(0).getDOM()
                                        .getTextContent();
                            }
                        }
                    }
                }
            }
        }
        return assertion.getSubject().getNameID().getValue();
    }

    /**
     * Get the X509CredentialImpl object for a particular tenant
     *
     * @param domainName domain name
     * @return X509CredentialImpl object containing the public certificate of that tenant
     * @throws SAML2SSOUIAuthenticatorException Error when creating X509CredentialImpl object
     */
    private static X509CredentialImpl getX509CredentialImplForTenant(String domainName)
            throws SAML2SSOUIAuthenticatorException {

        int tenantID = org.wso2.carbon.base.MultitenantConstants.SUPER_TENANT_ID;
        KeyStoreManager keyStoreManager = null;
        // get an instance of the corresponding Key Store Manager instance
        keyStoreManager = KeyStoreManager.getInstance(tenantID);
        X509CredentialImpl credentialImpl = null;
        String alias = SAML2SSOAuthFEDataHolder.getInstance().getIdPCertAlias();
        Key privateKey;
        try {
            if (tenantID != org.wso2.carbon.base.MultitenantConstants.SUPER_TENANT_ID) {
                // for non zero tenants, load private key from their generated key store
                KeyStore keystore = keyStoreManager.getKeyStore(generateKSNameFromDomainName(domainName));
                java.security.cert.X509Certificate cert =
                        (java.security.cert.X509Certificate) keystore.getCertificate(domainName);
                String ksName = domainName.trim().replace(".", "-");
                String jksName = ksName + ".jks";
                // obtain private key
                privateKey = keyStoreManager.getPrivateKey(jksName, domainName);
                credentialImpl = new X509CredentialImpl(cert, privateKey);
            } else {    // for tenant zero, load the cert corresponding to given alias in authenticators.xml
                privateKey = keyStoreManager.getDefaultPrivateKey();
                java.security.cert.X509Certificate cert = null;
                if (alias != null) {
                    cert = (java.security.cert.X509Certificate) keyStoreManager.getPrimaryKeyStore().getCertificate(alias);
                    if (cert == null) {
                        String errorMsg = "Cannot find a certificate with the alias " + alias +
                                " in the default key store. Please check the 'IdPCertAlias' property in" +
                                " the SSO configuration of the authenticators.xml";
                        throw new SAML2SSOUIAuthenticatorException(errorMsg);
                    }
                } else { // if the idpCertAlias is not given, use the default certificate.
                    cert = keyStoreManager.getDefaultPrimaryCertificate();
                }
                credentialImpl = new X509CredentialImpl(cert, privateKey);
            }
        } catch (SAML2SSOUIAuthenticatorException e) {
            String errorMsg = "Error instantiating an X509CredentialImpl object for the public cert.";
            throw new SAML2SSOUIAuthenticatorException(errorMsg, e);
        } catch (Exception e) {
            String errorMsg = "Error while loading the keystores.";
            throw new SAML2SSOUIAuthenticatorException(errorMsg, e);
        }
        return credentialImpl;
    }

    /**
     * To get the decrypted assertion.
     * @param encryptedAssertion encrypted assertion
     * @param domainName userstore domain name
     * @return encrypted SAML assertion
     * @throws SAML2SSOUIAuthenticatorException
     */
    public static Assertion getDecryptedAssertion(EncryptedAssertion encryptedAssertion, String domainName)
            throws SAML2SSOUIAuthenticatorException {

        X509Credential credential = getX509CredentialImplForTenant(domainName);
        try {
            KeyInfoCredentialResolver keyResolver = new StaticKeyInfoCredentialResolver(credential);
            EncryptedKey key = encryptedAssertion.getEncryptedData().getKeyInfo().getEncryptedKeys().get(0);
            Decrypter decrypter = new Decrypter(null, keyResolver, null);
            SecretKey dkey = (SecretKey) decrypter.decryptKey(key, encryptedAssertion.getEncryptedData().
                    getEncryptionMethod().getAlgorithm());
            Credential shared = SecurityHelper.getSimpleCredential(dkey);
            decrypter = new Decrypter(new StaticKeyInfoCredentialResolver(shared), null, null);
            decrypter.setRootInNewDocument(true);
            return decrypter.decrypt(encryptedAssertion);
        } catch (DecryptionException e) {
            throw new SAML2SSOUIAuthenticatorException("Error while decrypting the saml response.", e);
        }
    }

    private static String generateKSNameFromDomainName(String tenantDomain) {
        String ksName = tenantDomain.trim().replace(".", "-");
        return (ksName + ".jks");
    }

}

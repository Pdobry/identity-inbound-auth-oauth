/*
 * Copyright (c) 2017, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.oauth2.token;

import com.nimbusds.jose.Algorithm;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.JWTParser;
import com.nimbusds.jwt.PlainJWT;
import com.nimbusds.jwt.SignedJWT;
import net.minidev.json.JSONObject;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.oltu.oauth2.common.exception.OAuthSystemException;
import org.wso2.carbon.base.MultitenantConstants;
import org.wso2.carbon.core.util.KeyStoreManager;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.base.IdentityConstants;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.common.exception.InvalidOAuthClientException;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.authz.OAuthAuthzReqMessageContext;
import org.wso2.carbon.identity.oauth2.token.handlers.grant.AuthorizationGrantHandler;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.identity.openidconnect.CustomClaimsCallbackHandler;

import java.security.Key;
import java.security.interfaces.RSAPrivateKey;
import java.text.ParseException;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Collections;
import java.util.Date;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Self contained access token builder.
 */
public class JWTTokenIssuerCustom extends JWTTokenIssuer {

    // Signature algorithms.
    private static final String NONE = "NONE";
    private static final String SHA256_WITH_RSA = "SHA256withRSA";
    private static final String SHA384_WITH_RSA = "SHA384withRSA";
    private static final String SHA512_WITH_RSA = "SHA512withRSA";
    private static final String SHA256_WITH_HMAC = "SHA256withHMAC";
    private static final String SHA384_WITH_HMAC = "SHA384withHMAC";
    private static final String SHA512_WITH_HMAC = "SHA512withHMAC";
    private static final String SHA256_WITH_EC = "SHA256withEC";
    private static final String SHA384_WITH_EC = "SHA384withEC";
    private static final String SHA512_WITH_EC = "SHA512withEC";

    private static final String KEY_STORE_EXTENSION = ".jks";
    private static final String AUTHORIZATION_PARTY = "azp";
    private static final String AUDIENCE = "aud";

    private static final Log log = LogFactory.getLog(JWTTokenIssuer.class);

    // We are keeping a private key map which will have private key for each tenant domain. We are keeping this as a
    // static Map since then we don't need to read the key from keystore every time.
    private static Map<Integer, Key> privateKeys = new ConcurrentHashMap<>();
    private Algorithm signatureAlgorithm = null;

    public JWTTokenIssuerCustom() throws IdentityOAuth2Exception {

        if (log.isDebugEnabled()) {
            log.debug("Custom: JWT Access token builder is initiated");
        }

        OAuthServerConfiguration config = OAuthServerConfiguration.getInstance();

        // Map signature algorithm from identity.xml to nimbus format, this is a one time configuration.
        signatureAlgorithm = mapSignatureAlgorithm(config.getSignatureAlgorithm());
    }

    @Override
    public String accessToken(OAuthTokenReqMessageContext oAuthTokenReqMessageContext) throws OAuthSystemException {

        if (log.isDebugEnabled()) {
            log.debug("Custom: Access token request with token request message context. Authorized user " +
                    oAuthTokenReqMessageContext.getAuthorizedUser().toString());
        }

        try {
            if (oAuthTokenReqMessageContext.getScope().length > 0 && Arrays.asList(oAuthTokenReqMessageContext.getScope()).contains("spork")) {
                if (log.isDebugEnabled()) {
                		log.debug("Custom: has scope \"spork\"");
                }
                return this.customBuildJWTToken(oAuthTokenReqMessageContext);
            } else {
            		return super.accessToken(oAuthTokenReqMessageContext);      		
            }
        } catch (IdentityOAuth2Exception e) {
            throw new OAuthSystemException(e);
        }
    }


    /**
     * Build a signed jwt token from OauthToken request message context.
     *
     * @param request Token request message context.
     * @return Signed jwt string.
     * @throws IdentityOAuth2Exception
     */
    protected String customBuildJWTToken(OAuthTokenReqMessageContext request) throws IdentityOAuth2Exception {

        // Set claims to jwt token.
        JWTClaimsSet jwtClaimsSet = customCreateJWTClaimSet(null, request, request.getOauth2AccessTokenReqDTO()
                .getClientId());

        return customSignJWTWithRSA(jwtClaimsSet, request, null);
    }


    /**
     * Sign the JWT token with RSA (SHA-256, SHA-384, SHA-512) algorithm.
     *
     * @param jwtClaimsSet         JWT claim set to be signed.
     * @param tokenContext         Token context if available.
     * @param authorizationContext Authorization context if available.
     * @return Signed JWT token.
     * @throws IdentityOAuth2Exception
     */
    protected String customSignJWTWithRSA(JWTClaimsSet jwtClaimsSet, OAuthTokenReqMessageContext tokenContext,
                                    OAuthAuthzReqMessageContext authorizationContext) throws IdentityOAuth2Exception {

        try {
            String tenantDomain = null;

            tenantDomain = tokenContext.getAuthorizedUser().getTenantDomain();

            if (tenantDomain == null) {
                throw new IdentityOAuth2Exception("Cannot resolve the tenant domain of the user.");
            }

            int tenantId = IdentityTenantUtil.getTenantId(tenantDomain);

            Key privateKey;
            if (privateKeys.containsKey(tenantId)) {

                // PrivateKey will not be null because containsKey() true says given key is exist and ConcurrentHashMap
                // does not allow to store null values.
                privateKey = privateKeys.get(tenantId);
            } else {

                // Get tenant's key store manager.
                KeyStoreManager tenantKSM = KeyStoreManager.getInstance(tenantId);
                try {
                    privateKey = tenantKSM.getPrivateKey("testcert (1).jks", "1");
                } catch (Exception e) {
                    throw new IdentityOAuth2Exception("Error while obtaining private key for Spork", e);
                }

                // Add the private key to the static concurrent hash map for later uses.
                privateKeys.put(tenantId, privateKey);
            }

            JWSSigner signer = new RSASSASigner((RSAPrivateKey) privateKey);
            JWSHeader header = new JWSHeader((JWSAlgorithm) signatureAlgorithm);
            header.setKeyID("c2dce1ba7fa57e0f0def2d32d552eadc33159d39");
            JSONObject payloadJSON = jwtClaimsSet.toJSONObject();
            payloadJSON.put("aud", "https://identitytoolkit.googleapis.com/google.identity.identitytoolkit.v1.IdentityToolkit");
            JWSObject signedJWT = new JWSObject(header, new Payload(payloadJSON));
            signedJWT.sign(signer);
            return signedJWT.serialize();
        } catch (JOSEException e) {
            throw new IdentityOAuth2Exception("Error occurred while signing JWT", e);
        }
    }


    /**
     * Create a JWT claim set according to the JWT format.
     *
     * @param authAuthzReqMessageContext Oauth authorization request message context.
     * @param tokenReqMessageContext     Token request message context.
     * @param consumerKey                Consumer key of the application.
     * @return JWT claim set.
     * @throws IdentityOAuth2Exception
     */
    protected JWTClaimsSet customCreateJWTClaimSet(OAuthAuthzReqMessageContext authAuthzReqMessageContext,
                                             OAuthTokenReqMessageContext tokenReqMessageContext,
                                             String consumerKey) throws IdentityOAuth2Exception {

        // loading the stored application data
        OAuthAppDO oAuthAppDO;
        try {
            oAuthAppDO = OAuth2Util.getAppInformationByClientId(consumerKey);
        } catch (InvalidOAuthClientException e) {
            throw new IdentityOAuth2Exception("Error while retrieving app information for clientId: " + consumerKey, e);
        }

        AuthenticatedUser user;
        long accessTokenLifeTimeInMillis;
        if (authAuthzReqMessageContext != null) {
            user = authAuthzReqMessageContext.getAuthorizationReqDTO().getUser();
            accessTokenLifeTimeInMillis =
                    getAccessTokenLifeTimeInMillis(authAuthzReqMessageContext, oAuthAppDO, consumerKey);
        } else {
            user = tokenReqMessageContext.getAuthorizedUser();
            accessTokenLifeTimeInMillis =
                    getAccessTokenLifeTimeInMillis(tokenReqMessageContext, oAuthAppDO, consumerKey);
        }

        String issuer = "test-auth-3fb8a@appspot.gserviceaccount.com";
        long curTimeInMillis = Calendar.getInstance().getTimeInMillis();

        // Set the default claims.
        JWTClaimsSet jwtClaimsSet = new JWTClaimsSet();
        jwtClaimsSet.setIssuer(issuer);
        jwtClaimsSet.setSubject(issuer);
        jwtClaimsSet.setExpirationTime(new Date(curTimeInMillis + accessTokenLifeTimeInMillis));
        jwtClaimsSet.setIssueTime(new Date(curTimeInMillis));
        jwtClaimsSet.setJWTID(UUID.randomUUID().toString());
        jwtClaimsSet.setClaim("uid", user.getAuthenticatedSubjectIdentifier());

        // Handle custom claims
        if (authAuthzReqMessageContext != null) {
            handleCustomClaims(jwtClaimsSet, authAuthzReqMessageContext);
        } else {
            handleCustomClaims(jwtClaimsSet, tokenReqMessageContext);
        }

        return jwtClaimsSet;
    }


}

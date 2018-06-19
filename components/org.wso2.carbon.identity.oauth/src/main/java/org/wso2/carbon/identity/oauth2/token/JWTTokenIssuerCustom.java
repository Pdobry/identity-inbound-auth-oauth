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
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.common.exception.InvalidOAuthClientException;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.authz.OAuthAuthzReqMessageContext;
import org.wso2.carbon.identity.oauth2.internal.OAuth2ServiceComponentHolder;
import org.wso2.carbon.identity.oauth2.token.handlers.grant.AuthorizationGrantHandler;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.identity.openidconnect.CustomClaimsCallbackHandler;
import org.wso2.carbon.registry.core.Registry;
import org.wso2.carbon.registry.core.Resource;
import org.wso2.carbon.registry.core.exceptions.RegistryException;
import org.wso2.carbon.user.api.UserStoreException;

import java.security.Key;
import java.security.interfaces.RSAPrivateKey;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Collections;
import java.util.Date;
import java.util.Enumeration;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Self contained access token builder.
 */
public class JWTTokenIssuerCustom extends JWTTokenIssuer {


	private static final String SPORK_KEYSTORE_NAME = ".jks";
	private static final String SPORK_PRIVATE_KEY_NAME = "spork";
	private static final String SPORK_AUDIENCE = "https://identitytoolkit.googleapis.com/google.identity.identitytoolkit.v1.IdentityToolkit";
	private static final String SPORK_KEY_ID = "spork_key_id";
	private static final String SPORK_CLIENT_ID = "spork_client_id";
	
    private static final String USER_ID = "uid";
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
            log.info(Arrays.asList(oAuthTokenReqMessageContext.getScope()).toString());
            String sporkScopeName = "";
            
            if (oAuthTokenReqMessageContext.getScope().length > 0) {
	            List<String> scopes = Arrays.asList(oAuthTokenReqMessageContext.getScope());
	            for(String listItem : scopes){
	            	   if(listItem.contains("spork")){
	            		   sporkScopeName = listItem;
	            		   break;
	            	   }
	            	}                
            }
            
            
            if (sporkScopeName != "" ) {         
                if (log.isDebugEnabled()) {
                		log.debug("Custom: has scope \"" + sporkScopeName +" \"");
                }
                return this.customBuildJWTToken(oAuthTokenReqMessageContext, sporkScopeName);
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
    protected String customBuildJWTToken(OAuthTokenReqMessageContext request, String sporkName) throws IdentityOAuth2Exception {

        // Set claims to jwt token.
        JWTClaimsSet jwtClaimsSet = customCreateJWTClaimSet(null, request, request.getOauth2AccessTokenReqDTO()
                .getClientId());

        return customSignJWTWithRSA(jwtClaimsSet, request, null, sporkName);
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
                                    OAuthAuthzReqMessageContext authorizationContext, String sporkName) throws IdentityOAuth2Exception {

    		String spork_kid = "";
    		String spork_cid = "";
    		
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
                    privateKey = tenantKSM.getPrivateKey(sporkName + JWTTokenIssuerCustom.SPORK_KEYSTORE_NAME, JWTTokenIssuerCustom.SPORK_PRIVATE_KEY_NAME);
                } catch (Exception e) {
                    throw new IdentityOAuth2Exception("Error while obtaining private key for "+sporkName, e);
                }

                // Add the private key to the static concurrent hash map for later uses.
                privateKeys.put(tenantId, privateKey);
            }


            Registry registry = OAuth2ServiceComponentHolder.getRegistryService().getConfigSystemRegistry(tenantId);

            if (registry.resourceExists("/"+ sporkName)) {
                Resource resource = registry.get("/"+ sporkName);
                spork_kid = resource.getProperty(JWTTokenIssuerCustom.SPORK_KEY_ID);  
                spork_cid = resource.getProperty(JWTTokenIssuerCustom.SPORK_CLIENT_ID);  
            } else {
            	 	throw new IdentityOAuth2Exception("Cannot find Spork config in registry.");
            }
  
            JWSSigner signer = new RSASSASigner((RSAPrivateKey) privateKey);
            JWSHeader header = new JWSHeader((JWSAlgorithm) signatureAlgorithm);
            
            if (spork_kid.isEmpty() == false) {
            		header.setKeyID(spork_kid);
            }
            if (spork_cid.isEmpty() == false) {
	            	jwtClaimsSet.setIssuer(spork_cid);
	            jwtClaimsSet.setSubject(spork_cid);
            }
            
            JSONObject payloadJSON = jwtClaimsSet.toJSONObject();
            
            //write audience as a string - required by Firebase
            payloadJSON.put(JWTTokenIssuerCustom.AUDIENCE, JWTTokenIssuerCustom.SPORK_AUDIENCE);
            
            JWSObject signedJWT = new JWSObject(header, new Payload(payloadJSON));
            signedJWT.sign(signer);
            return signedJWT.serialize();
            
        }  catch (RegistryException e) {
            log.error("Error while getting data from the registry.", e);
            throw new IdentityOAuth2Exception("Error occurred while signing JWT", e);
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

        long curTimeInMillis = Calendar.getInstance().getTimeInMillis();

        // Set the default claims.
        JWTClaimsSet jwtClaimsSet = new JWTClaimsSet();

        jwtClaimsSet.setExpirationTime(new Date(curTimeInMillis + accessTokenLifeTimeInMillis));
        jwtClaimsSet.setIssueTime(new Date(curTimeInMillis));
        jwtClaimsSet.setJWTID(UUID.randomUUID().toString());
        jwtClaimsSet.setClaim(JWTTokenIssuerCustom.USER_ID, user.getAuthenticatedSubjectIdentifier());

        // Handle custom claims
        if (authAuthzReqMessageContext != null) {
            handleCustomClaims(jwtClaimsSet, authAuthzReqMessageContext);
        } else {
            handleCustomClaims(jwtClaimsSet, tokenReqMessageContext);
        }

        return jwtClaimsSet;
    }


}

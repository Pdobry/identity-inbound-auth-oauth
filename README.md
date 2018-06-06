# WSO2 IS OAuth module

## Overview

This is a fork from official WSO2 IS OAuth extension with added `JWTTokenIssuerCustom` module for providing JWT tokens signed with custom private key uses in Firebase project.

## Installation

1. Install WSO2 Identity Server. Current version is 5.4.1.
2. Build `org.wso2.carbon.identity.oauth_5.5.180.jar` file in Eclipse from this repository.
3. Copy the file to the **wso2is-5.4.1/repository/components/plugins** directory.

## Configuration

Edit **wso2is-5.4.1/repository/conf/identity/identity.xml** configuration file and add to `<OAuth>` section:

`<IdentityOAuthTokenGenerator>org.wso2.carbon.identity.oauth2.token.JWTTokenIssuerCustom</IdentityOAuthTokenGenerator>`

Then update the H2 database schema for WSO2 IS in file `dbscripts/identity/h2.sql` and change     values in IDN_OAUTH2_ACCESS_TOKEN table to:

`ACCESS_TOKEN VARCHAR (1024),`
`REFRESH_TOKEN VARCHAR (1024),`

If you've already started WSO2 IS application, you have to stop it, remove all databases from **wso2is-5.4.1/repository/databases** directory and start it with parameter `-D setup` to create new databases.

WSO2 Admin configuration:

1. Login to WSO2 IS Admin web interface (use admin/admin for login).
2. Add new `org.wso2.carbon.user.core.ldap.ActiveDirectoryUserStoreManager` user store in **User Stores**. Configure it to use your ActiveDirectory LDAP server. Set correct User Search Base and Username Attribute (eg. sAMAccountName).
3. Configure claims you want to use in **Claims** for dialect `http://wso2.org/claims`.
4. Go to **Registry -> Browse**  to edit the registry. In `/_system/config/oidc` create `spork` property with requested claims (eg. name, email, formatted, preferred_username).
5. Create Java KeyStore file (named spork.jks) with private auth key for Firebase and public key. I use KeyStore Explorer for this. Import the keystore to WSO2 IS (or opload the file to WSO2 IS Registry into `/_system/governance/repository/security/key-stores`). This private key will be used by JWTTokenIssuerCustom for signing JWT token.
6. In Service Providers create a new provider for your application and in Inbound Authentication Configuration - OAuth/OpenID Connect Configuration register new OAuth client. You'll get OAuth Client Key and password.
7. In WSO2 IS registry created a new object (eg. text) named `spork` in /_system/config and add properties `spork_key_id` (ID of private key from Firebase) and `spork_client_id` (Firebase account id) there.

## How to test it
I use Restlet Client extension in Chrome browser. Send HTTP POST request for URL `https://localhost:9443/oauth2/token` with Content-Type: application/x-www-form-urlencoded and Authorization Basic containing OAuth Client Key and password. Content is (replace username and password):

`grant_type=password&username=<username>&password=<password>&scope=spork`

You'll get a response like this:

`{
"access_token":  "eyJraWQiOiJjMmRjZTFiYTdmYTU3ZTBmMGRlZjJkMzJkNTUyZWFkYzMzMTU5ZDM5IiwiYWxnIjoiUlMyNTYifQ.eyJ1aWQiOiJQRE9CUlkuTEFCXC90ZWFjaGVyMiIsInN1YiI6InRlc3QtYXV0aC0zZmI4YUBhcHBzcG90LmdzZXJ2aWNlYWNjb3VudC5jb20iLCJhdWQiOiJodHRwczpcL1wvaWRlbnRpdHl0b29sa2l0Lmdvb2dsZWFwaXMuY29tXC9nb29nbGUuaWRlbnRpdHkuaWRlbnRpdHl0b29sa2l0LnYxLklkZW50aXR5VG9vbGtpdCIsIm5hbWUiOiJEdW1teSBUZWFjaGVyIiwiaXNzIjoidGVzdC1hdXRoLTNmYjhhQGFwcHNwb3QuZ3NlcnZpY2VhY2NvdW50LmNvbSIsInByZWZlcnJlZF91c2VybmFtZSI6IkR1bW15IFRlYWNoZXIiLCJleHAiOjE1MTk4MzQwODcsImlhdCI6MTUxOTgzMDQ4NywiZW1haWwiOiJkdW1teS50ZWFjaGVyQHNvbWVncmVhdHNjaG9vbC5jb20iLCJqdGkiOiI4ODVjNDBiOC04NDkyLTRjMWItYTEwNy1hM2U1NTJhMDViMjkifQ.XyvJOtv6S7Mihck\_btgbSHTbmvJZpiuOP95Wc8KpoDgvUH7gJmm6A3YRB3adlpIoLZE\_VZhcW9VKB55PQwP4C07jt\_Afgql\_bnnpzVpm427MGMRgTgJCQBrLmi16Gb\_2sjOlm9nrNNCBUOYoUoxh2i-rpWFJgHAF96ZYjCRK8naJrKqr4nv-zAotIb0ILgCoT0UF103DbvJ-97MOSxUa6Jeh1ppk2DS3RqH9uWTVXSzlG-KpBtlzpTakkeeoGalVlEgGMlko\_0YjfFdKDLxkDXmbBFZTh4JK1eSWn8KMY8LYdlzXc0VmPhJ5lJxUOTnnA0xoUHmrbdxxxLFFgIGoZg",",
"refresh_token":  "567539d0-6a31-342c-a873-7ca1be47633a",
"scope":  "spork",
"token_type":  "Bearer",
"expires_in":  3600
}
`

You can decode access_token at https://jwt.io:

> HEADER:ALGORITHM & TOKEN TYPE
> {
> 
>  "kid": "c2dce1ba7fa57e0f0def2d32d552eadc33159d39",
> 
>  "alg": "RS256"
> 
> }
> 
> PAYLOAD:DATA
> 
> {
> 
>  "uid": "PDOBRY.LAB/teacher2",
> 
>  "sub": "test-auth-3fb8a@appspot.gserviceaccount.com",
> 
>  "aud": "https://identitytoolkit.googleapis.com/google.identity.identitytoolkit.v1.IdentityToolkit",
> 
>  "name": "Dummy Teacher",
> 
>  "iss": "test-auth-3fb8a@appspot.gserviceaccount.com",
> 
>  "preferred_username": "Dummy Teacher",
> 
>  "exp": 1519834087,
> 
>  "iat": 1519830487,
> 
>  "email": "dummy.teacher@somegreatschool.com",
> 
>  "jti": "885c40b8-8492-4c1b-a107-a3e552a05b29"
> 
> }

# Authentication

Here is a workflow for user authentication using OAuth2 in WSO2 IS to get JWT token with user credentials. Spork web application uses user's login credentials to get signed JWT token from WSO2 IS web service. Spork web application must authenticate to WSO2 IS with own client's credentials. WSO2 IS then issues a JWT token in [Resource Owner Password Credentials Grant](https://docs.wso2.com/display/IS541/Resource+Owner+Password+Credentials+Grant) mode.
Signed JWT token is then used for authentication against Firebase as [Custom Token Auth](https://firebase.google.com/docs/auth/admin/create-custom-tokens) to get access to Firebase resources.

![Auth diagram](./img/auth.png)

# WSO2 IS & MS AD
To map users from Microsoft Active Directory, add new User Store with type of *org.wso2.carbon.user.core.ldap.ReadOnlyLDAPUserStoreManager*. If you're using Secure LDAP (LDAPS on port 636) with custom or self-signed certificate, make sure that the LDAP server SSL certificate is imported to WSO2. To import the certificate, you must obtain the server SSL certificate. Then open *wso2is/repository/resources/security/client-truststore.jks* file in JKS file editor (eg. KeyStore Explorer) and add the certificate file into the .jks file.

<!--stackedit_data:
eyJoaXN0b3J5IjpbMjA3MDQ5MjUzMiwtMTUzOTY1MTc1XX0=
-->
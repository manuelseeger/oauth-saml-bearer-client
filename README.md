# OAuth SAML Bearer Client

This is a basic implementation of an OauthSAMLBearer client as used by SAP Cloud 4 Customer (C4C).

The OAuthSAMLBearer flow allows a client application to make requests to the SAP OData API within the context of a regular user. No elevated permissions are required by the client application, and the OData API will respect access rights of the user in whose name the request is being made. 

## How to use

Setup an OAuth identity provider in C4C. Prepare the key and certificate of the identity provider in PEM format. 

Prepare a config object with the following properties:

| Property | Description |
|---|---|
| assertionTemplate | Path to an XML template file for the assertion. See [assets/assertion_template_minimal.xml](assets/assertion_template_minimal.xml) |
| clientId | ClientID of the OAuth token endpoint credentials |
| clientSecret | Secret of the OAuth token endpoint credentials |
| tokenEndPoint | URL of the OAuth token endpoint |
| entityId | SSO base URL of the C4C tenant |
| issuer | Name of the OAuth 2.0 identity provider configured in C4C |
| nameIdFormat | Format of the user ID, either emailAdress or unspecified |
| certificate | Certificate assigned to the OAuth identity provider in C4C (PEM string) |
| signingKey | Private key of the OAuth identity provider used for signing (PEM string) |
```js
const config = {
    assertionTemplate: 'assets/assertion_template_minimal.xml',
    clientId: '_1234567OGA',
    clientSecret: 'k4xv77E3qRIaLeDKnVQG',
    tokenEndPoint: 'https://my123456.crm.ondemand.com/sap/bc/sec/oauth2/token', 
    entityId: 'https://my123456-sso.crm.ondemand.com', 
    issuer: 'MY-IDP',
    nameIdFormat: 'emailAddress',
    certificate: await fs.readFile('cert.pem', { encoding: 'utf8' }),
    signingKey: await fs.readFile('key.pem', { encoding: 'utf8' })
}

const oauthClient = new OAuthSAMLBearerClient(config)

const nameId = 'jane.doe@company.info'

let tokenResponse = await oauthClient.requestToken(nameId)
```
If successful, the response is an [axios response object](https://axios-http.com/docs/res_schema) with a JSON payload containing token and validity.
```json
{
    "sdf": "sdf"
}
```
See also [examples/usage.js](examples/usage-axios.js)

Method requestToken will always query the token endpoint for a new token. If you use method getAccessToken, the client will cache the last valid token and only request a new one once validity expires.

This can be used to transparently request the token on requests to the OData API, for example with axios: 
```js
axios.interceptors.request.use(async axiosConfig => {
    const token = await oauthClient.getAccessToken(nameId)
    axiosConfig.headers.Authorization = `Bearer ${token}`
    return axiosConfig
})
```
See also [examples/usage-axios.js](examples/usage-axios.js)

## A word of caution
The C4C token endpoint API is extremely sensitive. The API will return 400 and a generic exception if there is the slightest deviation from the expected assertion format. The exception doesn't give any indication whether the error is in XML syntax, the signature, the expected values within the assertion, or anything else. All one can do is trial and error until it works. 

## Documentation
Documentation of the OAuth SAML Bearer flow is unfortunately rare. Here is a basic overview from SAP: 
https://wiki.scn.sap.com/wiki/display/Security/Using+OAuth+2.0+from+a+Web+Application+with+SAML+Bearer+Assertion+Flow

To set up a trusted third party who is allowed to authenticate users using the OAuthSAMLBearer flow, follow these instructions: 
https://help.sap.com/products/BTP/65de2977205c403bbc107264b8eccf4b/40d20a26f3dd445facff151b249fcf94.html

The OAuth SAML Bearer specification proposal: 
https://tools.ietf.org/id/draft-ietf-oauth-saml2-bearer-10.html

# OAuth SAML Bearer Client

This is a basic implementation of an OauthSAMLBearer client as used by SAP Cloud 4 Customer (C4C) and other SAP applications.

The OAuthSAMLBearer flow allows a client application to make requests to the SAP OData API within the context of a regular user. No elevated permissions are required by the client application, and the OData API will respect access rights of the user in whose name the request is being made.

## Usage

Setup an OAuth identity provider in the target application. Generate an SSL keypair for the identity provider and store the key and certificate of the identity provider in PEM format (see [generate.sh](test/fixture/generate.sh)).

Prepare a config object with the following properties:

| Property      | Description                                                                          |
| ------------- | ------------------------------------------------------------------------------------ |
| clientId      | ClientID of the OAuth token endpoint credentials                                     |
| clientSecret  | Secret of the OAuth token endpoint credentials                                       |
| tokenEndPoint | URL of the OAuth token endpoint                                                      |
| entityId      | SSO base URL of the target application tenant                                        |
| issuer        | Name of the OAuth 2.0 identity provider configured in target application             |
| nameIdFormat  | Format of the user ID, either emailAdress or unspecified                             |
| certificate   | Certificate assigned to the OAuth identity provider in C4C (PEM string)              |
| signingKey    | Private key of the OAuth identity provider used for signing (unencrypted PEM string) |

```js
import { OAuthSAMLBearerClient } from 'oauth-saml-bearer-client';
import fs from 'fs';

const certificate = fs.readFileSync('certificate.pem', 'utf8');
const private_key = fs.readFileSync('private_key.pem', 'utf8');

const client = new OAuthSAMLBearerClient({
    clientId: '_123456789',
    clientSecret: 'ABC123456789',
    entityId: 'HTTPS://my123456-sso.crm.ondemand.com',
    tokenEndPoint: 'https://my123456.crm.ondemand.com/sap/bc/sec/oauth2/token',
    issuer: 'MY-IDP',
    certificate: certificate,
    signingKey: private_key,
    nameIdFormat: 'emailAddress',
    scope: 'UIWC:CC_HOME',
});

const user = 'jane.doe@company.info';

const token = await client.getAccessToken(user);

console.log(token);
```

If successful, the response is an access token with scope and validity.

```json
{
    "access_token": "ABY-0tpvHtyn8V_Y0kZFExeEUsu41FIi9fP45VdLXfd2Mlf_",
    "token_type": "Bearer",
    "expires_in": "3600",
    "scope": "UIWC:CC_HOME"
}
```

### Optional settings

| Property          | Description                                                                                                                                                                      |
| ----------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| assertionTemplate | Custom template to build the assertion from. If not provided, [assets/assertion_template_minimal.xml](assets/assertion_template_minimal.xml) is used.                            |
| cacheTokens       | Optional boolean to indicate whether requested tokens should be cached in memory until they expire (default=false). If not set or false, client will always request a new token. |

This can be used to transparently request the token on requests to the OData API, for example with axios:

```js
axios.interceptors.request.use(async (axiosConfig) => {
    const token = await oauthClient.getAccessToken(nameId);
    axiosConfig.headers.Authorization = `Bearer ${token}`;
    return axiosConfig;
});
```

## Caution with server implementations (C4C)

The C4C token endpoint API is extremely sensitive. The API will return 400 and a generic exception if there is the slightest deviation from the expected assertion format. The exception doesn't give any indication whether the error is in XML syntax, the signature, the expected values within the assertion, or anything else. All one can do is trial and error until it works.

## Documentation

Documentation of the OAuth SAML Bearer flow is unfortunately rare. Here is a basic overview from SAP:
https://wiki.scn.sap.com/wiki/display/Security/Using+OAuth+2.0+from+a+Web+Application+with+SAML+Bearer+Assertion+Flow

To set up a trusted third party who is allowed to authenticate users using the OAuthSAMLBearer flow, follow these instructions:
https://help.sap.com/products/BTP/65de2977205c403bbc107264b8eccf4b/40d20a26f3dd445facff151b249fcf94.html

The OAuth SAML Bearer specification proposal:
https://tools.ietf.org/id/draft-ietf-oauth-saml2-bearer-10.html

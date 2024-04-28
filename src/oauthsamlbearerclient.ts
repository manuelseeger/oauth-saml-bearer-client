import { SignedXml } from 'xml-crypto';
import dayjs from 'dayjs';
import utc from 'dayjs/plugin/utc.js';
import { randomUUID } from 'crypto';
import { assertionTemplate as ASSERTION_TEMPLATE } from './assertiontemplate';

dayjs.extend(utc);

const DATE_TIME_FORMAT: string = 'YYYY-MM-DD[T]HH:mm:ss.SSS[Z]';

export interface OAuthSAMLBearerClientConfig {
    /**
     * The client ID of the OAuth client
     */
    clientId: string;
    /**
     * The client secret of the OAuth client
     */
    clientSecret: string;
    /**
     * The issuer of the assertion. This is the name of the OAuth identity provider
     */
    issuer: string;
    /**
     * The entity ID of the oauth service provider
     */
    entityId: string;
    /**
     * The token endpoint of the OAuth service provider
     */
    tokenEndPoint: URL;
    /**
     * The name ID format to use in the assertion. This can be either 'emailAddress' or 'unspecified'
     */
    nameIdFormat: 'emailAddress' | 'unspecified';
    /**
     * Optional: Overwrite the default assertion template.
     */
    assertionTemplate?: string;
    /**
     * The certificate to use for signing the assertion in PEM format.
     */
    certificate: string;
    /**
     * The unencrypted private key to use for signing the assertion in PEM format.
     */
    signingKey: string;
    /**
     * Optional: Cache the tokens for reuse. If set to true the token will be cached and reused until it expires.
     */
    cacheTokens?: boolean;
    /**
     * The scope of the OAuth token requested from the service provider
     */
    scope: string;
}

export interface AccessToken {
    access_token: string;
    token_type: string;
    expires_in: number;
    scope: string;
}

interface StoredAccessToken {
    token: AccessToken;
    expiryDate: dayjs.Dayjs;
}

export class OAuthSAMLBearerClient {
    protected config: OAuthSAMLBearerClientConfig;
    private refID: string;
    private _assertionTemplate?: string;

    public get assertionTemplate(): string {
        if (!this._assertionTemplate) {
            if (!this.config.assertionTemplate) {
                this._assertionTemplate = ASSERTION_TEMPLATE;
            } else {
                this._assertionTemplate = this.config.assertionTemplate;
            }
        }
        return this._assertionTemplate;
    }

    private _accessTokens: { [nameId: string]: StoredAccessToken } = {};

    /**
     * Constructor
     *
     * @param config OAuthSAMLBearerClientConfig configuration object
     * @param refId optional reference ID for the assertion, if not provided a random UUID will be generated
     */
    constructor(config: OAuthSAMLBearerClientConfig, refId?: string) {
        this.config = config;
        if (refId) {
            this.refID = refId;
        } else {
            this.refID = `A_${randomUUID()}`;
        }
    }

    /**
     * Get an access token for the given nameId. If cacheTokens is set to true in the configuration
     * the token will be cached and reused until it expires.
     * If cacheTokens is not set or set to false the token will be requested from the token endpoint
     * for every call.
     *
     * @param nameId the nameId of the user to get the token for
     * @returns a promise that resolves to an AccessToken
     */
    public async getAccessToken(nameId: string): Promise<AccessToken> {
        if (!this.config.cacheTokens) {
            return this.requestToken(nameId);
        }
        if (
            !this._accessTokens[nameId] ||
            this._accessTokens[nameId].expiryDate.isBefore(dayjs())
        ) {
            const token: AccessToken = await this.requestToken(nameId);
            this._accessTokens[nameId] = {
                token: token,
                expiryDate: dayjs().add(token.expires_in, 'second'),
            };
        }
        return this._accessTokens[nameId].token;
    }

    /**
     * Request a new token from the token endpoint for the given nameId
     *
     * @param nameId the nameId to use in the assertion
     * @returns a promise that resolves to an AccessToken
     */
    protected async requestToken(nameId: string): Promise<AccessToken> {
        let assertion = this.getAssertion(nameId);
        let signedAssertion = this.signAssertion(assertion);

        let payload = new URLSearchParams({
            client_id: this.config.clientId,
            grant_type: 'urn:ietf:params:oauth:grant-type:saml2-bearer',
            scope: this.config.scope,
            assertion: Buffer.from(signedAssertion).toString('base64'),
        }).toString();

        const headers = new Headers();
        headers.set(
            'Authorization',
            'Basic ' +
                Buffer.from(
                    this.config.clientId + ':' + this.config.clientSecret,
                ).toString('base64'),
        );
        headers.set('Content-Type', 'application/x-www-form-urlencoded');

        const tokenResponse = await fetch(
            this.config.tokenEndPoint.toString(),
            {
                method: 'POST',
                headers: headers,
                body: payload,
            },
        );
        return tokenResponse.json() as Promise<AccessToken>;
    }

    /**
     * Get the assertion for the given nameId. This will replace all placeholders in the
     * assertion template with the values from the configuration and the nameId.
     *
     * @param nameId The nameId to use in the assertion
     * @returns
     */
    protected getAssertion(nameId: string) {
        let assertion = this.assertionTemplate;

        const replacements: { [key: string]: string } = {
            '@ISSUER': this.config.issuer,
            '@NAME_ID': nameId,
            '@TOKEN_SERVICE_URL': this.config.tokenEndPoint.toString(),
            '@SP_ENTITY_ID': this.config.entityId,
            '@ISSUE_INSTANT': dayjs().utc().format(DATE_TIME_FORMAT),
            '@NOT_AFTER': dayjs()
                .utc()
                .add(10, 'minute')
                .format(DATE_TIME_FORMAT),
            '@NOT_BEFORE': dayjs().utc().format(DATE_TIME_FORMAT),
            '@CLIENT_ID': this.config.clientId,
            '@REF_ID': this.refID,
            '@NAMEID_FORMAT': this.config.nameIdFormat,
        };
        for (const key in replacements) {
            assertion = assertion.replaceAll(key, replacements[key]);
        }
        return assertion;
    }

    /**
     * Sign the assertion using the configured certificate and private key
     *
     * @param assertionXml The assertion to sign
     * @returns the signed assertion
     */
    protected signAssertion(assertionXml: string) {
        const sign = new SignedXml({
            publicCert: this.config.certificate,
            privateKey: this.config.signingKey,
        });

        const transforms = [
            'http://www.w3.org/TR/2001/REC-xml-c14n-20010315',
            'http://www.w3.org/2000/09/xmldsig#enveloped-signature',
        ];
        sign.canonicalizationAlgorithm =
            'http://www.w3.org/TR/2001/REC-xml-c14n-20010315';
        sign.signatureAlgorithm =
            'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256';
        sign.addReference({
            xpath: `//*[@id='${this.refID}']`,
            transforms: transforms,
            digestAlgorithm: 'http://www.w3.org/2001/04/xmlenc#sha256',
        });

        sign.computeSignature(assertionXml);
        return sign.getSignedXml();
    }
}

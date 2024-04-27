import { SignedXml } from 'xml-crypto'
import dayjs from 'dayjs'
import utc from 'dayjs/plugin/utc.js'
import { randomUUID } from 'crypto'
import path from 'path'
import fs from 'fs'

dayjs.extend(utc)

export type NameIdFormat = 'emailAddress' | 'unspecified';

export interface OAuthSAMLBearerClientConfig {
    clientId: string
    clientSecret: string
    issuer: string
    entityId: string
    tokenEndPoint: URL
    assertionTemplate: string
    nameIdFormat: NameIdFormat
    key: string
    certificate: string
    signingKey: string
    cacheTokens?: boolean
}

export interface AccessToken {
    access_token: string
    token_type: string
    expires_in: number
    scope: string
}

interface StoredAccessToken {
    token: AccessToken
    expiryDate: dayjs.Dayjs
}

export default class OAuthSAMLBearerClient {

    private DATE_TIME_FORMAT: string = "YYYY-MM-DD[T]HH:mm:ss.SSS[Z]";
    public config: OAuthSAMLBearerClientConfig;
    private refID: string;
    private _assertionTemplate?: string;

    public get assertionTemplate(): string {
        if (!this._assertionTemplate) {
            this._assertionTemplate = fs.readFileSync(path.join('assets', this.config.assertionTemplate), { encoding: 'utf8' })
        }
        return this._assertionTemplate;
    }

    private _accessTokens: {[nameId: string]: StoredAccessToken} = {}

    constructor(config: OAuthSAMLBearerClientConfig) {
        this.config = config
        this.refID = `A_${randomUUID()}`        
    }

    public async getAccessToken(nameId: string) {
        if (!this.config.cacheTokens) {
            return this.requestToken(nameId)
        }
        if (!this._accessTokens[nameId] || this._accessTokens[nameId].expiryDate.isBefore(dayjs())) {
            const token: AccessToken = await this.requestToken(nameId)
            this._accessTokens[nameId] = {
                token: token,
                expiryDate: dayjs().add(token.expires_in, 'second')
            }
        }
        return this._accessTokens[nameId].token
    }

    protected async requestToken(nameId: string): Promise<AccessToken> {
        let assertion = await this.getAssertion(nameId)
        let signedAssertion = await this.signAssertion(assertion)

        let payload = new URLSearchParams({
            client_id: this.config.clientId,
            grant_type: 'urn:ietf:params:oauth:grant-type:saml2-bearer',
            scope: 'UIWC:CC_HOME',
            assertion: Buffer.from(signedAssertion).toString('base64')
        }).toString()

        const headers = new Headers();
        headers.set('Authorization', 'Basic ' + Buffer.from(this.config.clientId 
            + ":" + this.config.clientSecret).toString('base64'));
        headers.set('Content-Type', 'application/x-www-form-urlencoded');


        const tokenResponse = await fetch(this.config.tokenEndPoint, {
            method: 'POST',
            headers: headers,
            body: payload
        });
        return tokenResponse.json() as Promise<AccessToken>;      
    }

    protected async getAssertion(nameId: string) {

        let assertion = this.assertionTemplate

        let replacements : {[key: string]: string} = {
            '@ISSUER': this.config.issuer,
            '@NAME_ID': nameId, 
            '@TOKEN_SERVICE_URL': this.config.tokenEndPoint.toString(),
            '@SP_ENTITY_ID': this.config.entityId,
            '@ISSUE_INSTANT': dayjs().utc().format(this.DATE_TIME_FORMAT),
            '@NOT_AFTER': dayjs().utc().add(10, 'minute').format(this.DATE_TIME_FORMAT),
            '@NOT_BEFORE': dayjs().utc().format(this.DATE_TIME_FORMAT),
            '@CLIENT_ID': this.config.clientId,
            '@REF_ID': this.refID,
            '@NAMEID_FORMAT': this.config.nameIdFormat
        }
        for (let key in replacements) {
            assertion = assertion.replaceAll(key, replacements[key])
        }
        return assertion
    }

    protected async signAssertion(assertionXml: string) {
        const sign = new SignedXml({
            publicCert: this.config.certificate,
            privateKey: this.config.signingKey
        });

        const transforms = [
            'http://www.w3.org/TR/2001/REC-xml-c14n-20010315', 
            'http://www.w3.org/2000/09/xmldsig#enveloped-signature'
        ]
        sign.canonicalizationAlgorithm = 'http://www.w3.org/TR/2001/REC-xml-c14n-20010315'
        sign.signatureAlgorithm = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256'
        sign.addReference({
            xpath:`//*[@id='${this.refID}']`,
            transforms: transforms,
            digestAlgorithm: 'http://www.w3.org/2001/04/xmlenc#sha256' 
        });
        
        sign.computeSignature(assertionXml)
        return sign.getSignedXml()
    }
}

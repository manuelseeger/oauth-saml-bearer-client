import { SignedXml } from 'xml-crypto'
import fs from 'fs/promises'
import dayjs from 'dayjs'
import utc from 'dayjs/plugin/utc.js'
import { randomUUID } from 'crypto'
import axios from 'axios'
import path from 'path'

dayjs.extend(utc)

export {
    OAuthSAMLBearerClient
}

class ConfigKeyInfo {
    constructor(key, cert) {
        this.cert = cert.split('\r\n').slice(1,-2).join('')
        this.key = key
    }
      
    getKeyInfo(key, prefix) {
        prefix = prefix || ''
        prefix = prefix ? prefix + ':' : prefix
        return `<${prefix}X509Data><${prefix}X509Certificate>${this.cert}</${prefix}X509Certificate></${prefix}X509Data>`
    }
      
    getKey(keyInfo) {
        return this.key
    }
}  

export default class OAuthSAMLBearerClient {

    DATE_TIME_FORMAT = "YYYY-MM-DD[T]HH:mm:ss.SSS[Z]"
    debug = false

    constructor(config) {
        this.config = config
        this.refID = `A_${randomUUID()}`
        this.assertionTemplate = fs.readFile(path.join('assets', this.config.assertionTemplate), { encoding: 'utf8' })
    }

    async getAccessToken(nameId) {
        if (!this._accessToken || this._expiryDate.isBefore(dayjs())) {
            const tokenResponse = await this.requestToken(nameId)
            const { access_token, token_type, expires_in, scope } = tokenResponse.data
            this._expiryDate = dayjs().add(expires_in, 'second')
            this._accessToken = access_token
        }
        return this._accessToken
    }

    async requestToken(nameId) {
        let assertion = await this.getAssertion(nameId)
        let signedAssertion = await this.signAssertion(assertion)

        if (this.debug) {
            fs.writeFile('_debugassertion.xml', signedAssertion)
        }

        let requestConfig = {
            auth: {
                username: this.config.clientId,
                password: this.config.clientSecret
            }
        }

        let payload = new URLSearchParams({
            client_id: this.config.clientId,
            grant_type: 'urn:ietf:params:oauth:grant-type:saml2-bearer',
            scope: 'UIWC:CC_HOME',
            assertion: Buffer.from(signedAssertion).toString('base64')
        }).toString()

        try {
            let tokenResponse = await axios.post(this.config.tokenEndPoint, payload, requestConfig)
            return tokenResponse
        } catch (e) {
            if (e.response) {
                console.log(e)
                console.log(e.response.data.error)
                console.log(e.response.data.error_description)
            }
        }        
    }

    async getAssertion(nameId) {

        let assertion = await this.assertionTemplate

        let replacements = {
            '@ISSUER': this.config.issuer,
            '@NAME_ID': nameId, 
            '@TOKEN_SERVICE_URL': this.config.tokenEndPoint,
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

    async signAssertion(assertionXml) {
        const sign = new SignedXml()

        if (!!this.config.certificate) {
            sign.keyInfoProvider = new ConfigKeyInfo(this.config.key, this.config.certificate)
        }
        
        const transforms = ['http://www.w3.org/TR/2001/REC-xml-c14n-20010315', 'http://www.w3.org/2000/09/xmldsig#enveloped-signature']
        sign.canonicalizationAlgorithm = 'http://www.w3.org/TR/2001/REC-xml-c14n-20010315'
        sign.signatureAlgorithm = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256'
        sign.addReference(`//*[@id='${this.refID}']`, transforms, 'http://www.w3.org/2001/04/xmlenc#sha256')
        sign.signingKey = this.config.signingKey
        sign.computeSignature(assertionXml)
        return sign.getSignedXml()
    }
}

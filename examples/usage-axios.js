import { OAuthSAMLBearerClient } from '../oauthsamlbearerclient.js'
import fs from 'fs/promises'
import path from 'path'
import { Command } from 'commander'
import axios from 'axios'


(async () => {
    const program = new Command()
    program
        .argument('<NameID>', 'User to request token for')
        .parse()

    const nameId = program.processedArgs[0]

    const config = {
        assertionTemplate: process.env.ASSERTION_TEMPLATE,
        clientId: process.env.CLIENT_ID,
        clientSecret: process.env.CLIENT_SECRET,
        tokenEndPoint: process.env.TOKEN_ENDPOINT, 
        entityId: process.env.ENTITY_ID, 
        issuer: process.env.ISSUER,
        nameIdFormat: 'emailAddress',
        certificate: await fs.readFile(path.join('assets', process.env.CERTIFICATE_FILE), { encoding: 'utf8' }),
        signingKey: await fs.readFile(path.join('assets', process.env.KEY_FILE), { encoding: 'utf8' })
    }

    const oauthClient = new OAuthSAMLBearerClient(config)
    // write _debugassertion.xml to CWD
    oauthClient.debug = true

    const c4c = axios.create({
        baseURL: `https://${process.env.TENANT}.crm.ondemand.com/sap/c4c/odata/v1`,
    })
    c4c.interceptors.request.use(async axiosConfig => {
        const token = await oauthClient.getAccessToken(nameId)
        console.log('Token', token)
        axiosConfig.headers.Authorization = `Bearer ${token}`
        return axiosConfig
    })

    // first request to the API, will authenticate user
    let customerResponse = await c4c.get('/customer/IndividualCustomerCollection', {
        params: {
            '$top': 1
        }
    })
    console.log(customerResponse)

    // second request, will use stored token 
    let leadResponse = await c4c.get('/lead/LeadCollection', {
        params: {
            '$top': 1
        }
    })
    console.log(leadResponse)

})();

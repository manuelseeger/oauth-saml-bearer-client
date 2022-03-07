import { OAuthSAMLBearerClient, P12KeyInfo } from './oauthsamlbearerclient.js'
import fs from 'fs/promises'
import path from 'path'
import { Command } from 'commander';


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

    const oauth = new OAuthSAMLBearerClient(config)
    oauth.debug = true
/*
    const p12 = new P12KeyInfo('assets/spc-uat-config-UAT-SAP-OneLogin-AuthSamlBearer-20220217.pfx', '')

    

    const assertionXml = await oauth.getAssertion('manuel.seeger@swisslife.ch')

    const signedAssertion = await oauth.signAssertion(assertionXml)

    console.log(signedAssertion)

    await fs.writeFile(path.join('assets', '_debugassertion.xml'), signedAssertion)
*/
    let ret = await oauth.requestToken(nameId)
    
    console.log(ret, ret.data)

})();
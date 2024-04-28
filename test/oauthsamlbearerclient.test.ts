import {
    OAuthSAMLBearerClient,
    OAuthSAMLBearerClientConfig,
} from '../src/oauthsamlbearerclient';
import { enableFetchMocks } from 'jest-fetch-mock';
import fs from 'fs';
import path from 'path';

enableFetchMocks();

beforeEach(() => {
    fetchMock.resetMocks();
});

describe('OAuthSAMLBearerClient', () => {
    const certificate = fs.readFileSync(
        path.join(__dirname, 'fixture', 'certificate.pem'),
        'utf8',
    );
    const privateKey = fs.readFileSync(
        path.join(__dirname, 'fixture', 'private_key.pem'),
        'utf8',
    );

    it('constructor should match snapshot', async () => {
        const config: OAuthSAMLBearerClientConfig = {
            clientId: '_ABC123456',
            clientSecret: '1234567890',
            entityId: 'HTTPS://my123456-sso.crm.ondemand.com',
            tokenEndPoint: new URL(
                'https://my123456.crm.ondemand.com/sap/bc/sec/oauth2/token',
            ),
            issuer: 'unit-test',
            certificate: 'certificate',
            signingKey: 'private_key',
            nameIdFormat: 'emailAddress',
            scope: 'UIWC:CC_HOME',
            assertionTemplate:
                '<Assertion ID="@REF_ID"><custom></custom></Assertion>',
        };
        const client = new OAuthSAMLBearerClient(config, 'A_unit-test');

        expect(client).toBeInstanceOf(OAuthSAMLBearerClient);
        expect(client.assertionTemplate).toEqual(
            '<Assertion ID="@REF_ID"><custom></custom></Assertion>',
        );
        expect(client).toMatchSnapshot();
    });

    it('should get token', async () => {
        const name = 'test.user@unit.test';

        const config: OAuthSAMLBearerClientConfig = {
            clientId: '_ABC123456',
            clientSecret: '1234567890',
            entityId: 'HTTPS://my123456-sso.crm.ondemand.com',
            tokenEndPoint: new URL(
                'https://my123456.crm.ondemand.com/sap/bc/sec/oauth2/token',
            ),
            issuer: 'unit-test',
            certificate: certificate,
            signingKey: privateKey,
            nameIdFormat: 'emailAddress',
            scope: 'UIWC:CC_HOME',
        };
        const client = new OAuthSAMLBearerClient(config);

        fetchMock.mockResponseOnce(
            JSON.stringify({
                access_token: 'access_token',
                token_type: 'Bearer',
                expires_in: 3600,
                scope: 'UIWC:CC_HOME',
            }),
        );

        const token = await client.getAccessToken(name);
        expect(token).toEqual({
            access_token: 'access_token',
            token_type: 'Bearer',
            expires_in: 3600,
            scope: 'UIWC:CC_HOME',
        });
    });

    it('should get token from cache', async () => {
        const name = 'test.user@unit.test';

        const config: OAuthSAMLBearerClientConfig = {
            clientId: '_ABC123456',
            clientSecret: '1234567890',
            entityId: 'HTTPS://my123456-sso.crm.ondemand.com',
            tokenEndPoint: new URL(
                'https://my123456.crm.ondemand.com/sap/bc/sec/oauth2/token',
            ),
            issuer: 'unit-test',
            certificate: certificate,
            signingKey: privateKey,
            nameIdFormat: 'emailAddress',
            scope: 'UIWC:CC_HOME',
            cacheTokens: true,
        };
        const client = new OAuthSAMLBearerClient(config);

        fetchMock.mockResponse(
            JSON.stringify({
                access_token: 'access_token',
                token_type: 'Bearer',
                expires_in: 3600,
                scope: 'UIWC:CC_HOME',
            }),
        );

        const token = await client.getAccessToken(name);
        const token2 = await client.getAccessToken(name);

        expect(token2).toEqual(token);
        expect(fetchMock).toHaveBeenCalledTimes(1);
    });
});

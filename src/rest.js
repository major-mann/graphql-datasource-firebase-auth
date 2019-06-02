module.exports = createRestInterface;

const VERIFY_PASSWORD_URI = apiKey => `https://www.googleapis.com/identitytoolkit/v3/relyingparty/verifyPassword` +
    `?key=${encodeURIComponent(apiKey)}`;
const VERIFY_CUSTOM_TOKEN_URI = apiKey => `https://www.googleapis.com/identitytoolkit/v3/relyingparty/verifyCustomToken` +
    `?key=${apiKey}`
const REFRESH_ID_TOKEN_URI = apiKey => `https://securetoken.googleapis.com/v1/token?key=${apiKey}`;

const VERIFY_PASSWORD_RESPONSE = 'identitytoolkit#VerifyPasswordResponse';
const VERIFY_CUSTOM_TOKEN_RESPONSE = 'identitytoolkit#VerifyCustomTokenResponse';

const fetch = require('node-fetch');

function createRestInterface(apiKey) {
    const verifyPasswordUri = VERIFY_PASSWORD_URI(apiKey);
    const verifyCustomTokenUri = VERIFY_CUSTOM_TOKEN_URI(apiKey);
    const refreshIdTokenUri = REFRESH_ID_TOKEN_URI(apiKey);

    return {
        refreshIdToken,
        verifyPassword,
        verifyCustomToken
    };

    async function verifyPassword(email, password) {
        const response = await post(verifyPasswordUri, VERIFY_PASSWORD_RESPONSE, {
            email,
            password,
            returnSecureToken: true
        });
        return response;
    }

    async function verifyCustomToken(token) {
        const response = await post(verifyCustomTokenUri, VERIFY_CUSTOM_TOKEN_RESPONSE, {
            token,
            returnSecureToken: true
        });
        return response;
    }

    async function refreshIdToken(refreshToken) {
        const response = await post(refreshIdTokenUri, undefined, {
            grant_type: 'refresh_token',
            refresh_token: refreshToken
        });
        return response;
    }

    async function post(uri, responseType, data) {
        if (!apiKey) {
            throw new Error('No API key available. Unable to make call to API');
        }

        const response = await fetch(uri, {
            method: 'POST',
            headers: { 'content-type': 'application/json' },
            body: JSON.stringify(data)
        });

        const body = isJson(response.headers.get('content-type')) ?
            await response.json() :
            await response.text();

        if (response.ok) {
            if (body && body.kind === responseType) {
                return body;
            } else {
                throw new Error(`Invalid response kind ${JSON.stringify(body && body.kind)} received. ` +
                    `Expected ${JSON.stringify(responseType)}`);
            }
        } else if (body && typeof body === 'object') {
            if (body.error && typeof body.error === 'object') {
                body = body.error;
            }
            throw Object.assign(new Error(body.message), body);
        } else {
            throw new Error(body);
        }
    }

    function isJson(contentType) {
        if (contentType) {
            const [type] = contentType.split(';');
            console.log(type);
            return type && type.trim() === 'application/json';
        } else {
            return false;
        }
    }
}

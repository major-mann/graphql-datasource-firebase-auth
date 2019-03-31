module.exports = createRestInterface;

const VERIFY_PASSWORD_URI = apiKey => `https://www.googleapis.com/identitytoolkit/v3/relyingparty/verifyPassword` +
    `?key=${encodeURIComponent(apiKey)}`;

const VERIFY_PASSWORD_RESPONSE = 'identitytoolkit#VerifyPasswordResponse';

const fetch = require('node-fetch');

function createRestInterface(apiKey) {
    const verifyPasswordUri = VERIFY_PASSWORD_URI(apiKey);

    return {
        verifyPassword
    };

    async function verifyPassword(email, password) {
        if (!apiKey) {
            throw new Error('No API key available. Unable to generate an ID token');
        }

        const response = await fetch(verifyPasswordUri, {
            method: 'POST',
            headers: { 'content-type': 'application/json' },
            body: JSON.stringify({
                email,
                password,
                returnSecureToken: true
            })
        });

        const body = isJson(response.headers.get('content-type')) ?
            await response.json() :
            await response.text();

        if (response.ok) {
            if (body && body.kind === VERIFY_PASSWORD_RESPONSE) {
                return body.idToken;
            } else {
                throw new Error(`Invalid response "${body && body.kind}" received. ` +
                    `Expected ${VERIFY_PASSWORD_RESPONSE}`);
            }
        } else if (typeof body === 'object') {
            throw Object.assign(new Error(), body);
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
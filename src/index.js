module.exports = createGraphqlFirebaseAuthSource;

const createGraphqlDatasource = require(`@major-mann/graphql-datasource-base`);
const createFirebaseAuthDatasource = require(`@major-mann/datasource-firebase-auth`);
const createRest = require(`./rest.js`);

async function createGraphqlFirebaseAuthSource({ apiKey, auth }) {
    const collections = new WeakMap();
    const restClients = {};
    // TODO: Want a created date
    //      metadata.creationTime
    const composer = await createGraphqlDatasource({
        definitions: `
            type User {
                uid: ID!
                email: String
                emailVerified: Boolean
                phoneNumber: String
                disabled: Boolean!
                link: UserLink!
            }

            type UserLink {
                verification: String!
                signIn: String!
                passwordReset: String!
            }

            input UserInput {
                email: String
                password: String
                emailVerified: Boolean
                phoneNumber: String
                disabled: Boolean
            }

            input UserUpdateInput {
                email: String
                password: String
                emailVerified: Boolean
                phoneNumber: String
                disabled: Boolean
            }
        `,
        rootTypes: [`User`],
        data: loadCollection
    });

    composer.createObjectTC({
        name: `IdTokenResponse`,
        fields: {
            idToken: `String!`,
            refreshToken: `String!`,
            expiresIn: `Int!`,
            email: `String!`,
            localId: `String!`,
            registered: `Boolean!`
        }
    });

    composer.createObjectTC({
        name: `RefreshTokenResponse`,
        fields: {
            idToken: `String!`,
            refreshToken: `String!`,
            expiresIn: `Int!`,
            tokenType: `String!`,
            userId: `String!`,
            projectId: `String!`
        }
    });

    const userLinkType = composer.getOTC(`UserLink`);
    userLinkType.addResolver({
        name: `$verification`,
        type: `String!`,
        resolve: verification
    });
    userLinkType.addResolver({
        name: `$signIn`,
        type: `String!`,
        resolve: signIn
    });
    userLinkType.addResolver({
        name: `$passwordReset`,
        type: `String!`,
        resolve: passwordReset
    });

    userLinkType.setField(`verification`, userLinkType.getResolver(`$verification`));
    userLinkType.setField(`signIn`, userLinkType.getResolver(`$signIn`));
    userLinkType.setField(`passwordReset`, userLinkType.getResolver(`$passwordReset`));

    composer.getOTC(`User`).addFields({ link: { type: `UserLink`, resolve: user => user } });

    const tokenType = composer.createObjectTC({ name: `Token` })
        .addResolver({
            name: `$id`,
            type: `IdTokenResponse`,
            resolve: id,
            args: {
                email: `String`,
                password: `String`,
                customToken: `String`
            }
        })
        .addResolver({
            name: `$refresh`,
            type: `RefreshTokenResponse`,
            resolve: refresh,
            args: {
                refreshToken: `String`
            }
        })
        .addResolver({
            name: `$verify`,
            type: `Boolean`,
            resolve: verify,
            args: {
                idToken: `String`,
                sessionToken: `String`,
                checkRevoked: `Boolean`
            }
        })
        .addResolver({
            name: `$session`,
            type: `String`,
            resolve: session,
            args: {
                idToken: `String!`,
                expiresIn: `Int`
            }
        })
        .addResolver({
            name: `$custom`,
            type: `String`,
            resolve: custom,
            args: {
                uid: `ID!`,
                claims: `String`
            }
        })
        .addResolver({
            name: `$revoke`,
            type: `Boolean`,
            resolve: revoke,
            args: { uid: `ID` }
        });

    tokenType.addFields({
        id: tokenType.getResolver(`$id`),
        refresh: tokenType.getResolver(`$refresh`),
        verify: tokenType.getResolver(`$verify`),
        session: tokenType.getResolver(`$session`),
        custom: tokenType.getResolver(`$custom`),
        revoke: tokenType.getResolver(`$revoke`)
    });

    composer.Query.addFields({ token: { type: `Token`, resolve: () => ({}) } });
    return composer;

    function loadRest({ context }) {
        let actualApiKey;
        if (typeof apiKey === `function`) {
            actualApiKey = apiKey({ context });
        } else {
            actualApiKey = apiKey;
        }
        if (!restClients[actualApiKey]) {
            restClients[actualApiKey] = createRest(actualApiKey);
        }
        return restClients[actualApiKey];
    }

    async function loadCollection({ context }) {
        let actualAuth;
        if (typeof auth === `function`) {
            actualAuth = auth({ context });
        } else {
            actualAuth = auth;
        }
        if (collections.has(actualAuth)) {
            return collections.get(actualAuth);
        } else {
            const contextualLoadCollection = createFirebaseAuthDatasource({ auth: actualAuth });
            collections.set(actualAuth, contextualLoadCollection);
            return contextualLoadCollection;
        }
    }

    async function signIn({ source }) {
        const link = await auth.generateSignInWithEmailLink(source.email);
        return link;
    }

    async function verification({ source }) {
        const link = await auth.generateEmailVerificationLink(source.email);
        return link;
    }

    async function passwordReset({ source }) {
        const link = await auth.generatePasswordResetLink(source.email);
        return link;
    }

    async function id({ args, context }) {
        let tokenData;
        const rest = loadRest({ context });
        if (typeof args.email === `string` && typeof args.password === `string`) {
            tokenData = await rest.verifyPassword(args.email, args.password);
        } else if (typeof args.customToken === `string`) {
            tokenData = await rest.verifyCustomToken(args.customToken);
        } else {
            throw new Error(`Either email and password must be supplied or "customToken"`);
        }
        return tokenData;
    }

    async function refresh({ args, context }) {
        const rest = loadRest({ context });
        const refreshTokenData = await rest.refreshIdToken(args.refreshToken);
        return {
            idToken: refreshTokenData.id_token,
            refreshToken: refreshTokenData.refresh_token,
            expiresIn: parseInt(refreshTokenData.expires_in),
            tokenType: refreshTokenData.token_type,
            userId: refreshTokenData.user_id,
            projectId: refreshTokenData.project_id
        };
    }

    async function verify({ args }) {
        if (args.idToken) {
            const claims = await auth.verifyIdToken(args.idToken, Boolean(args.checkRevoked));
            return claims;
        } else if (args.sessionToken) {
            const claims = await auth.verifySessionCookie(args.sessionToken, Boolean(args.checkRevoked));
            return claims;
        } else {
            throw new Error(`MUST supply either idToken or session token`);
        }
    }

    async function custom({ args }) {
        const claims = parseClaims(args.claims);
        const token = await auth.createCustomToken(args.uid, claims);
        return token;

        function parseClaims(claimsStr) {
            try {
                return args.claims && JSON.parse(claimsStr);
            } catch (ex) {
                return undefined;
            }
        }
    }

    async function session({ args }) {
        const token = await auth.createSessionCookie(args.idToken, {
            expiresIn: args.expiresIn
        });
        return token;
    }

    async function revoke({ args }) {
        await auth.revokeRefreshTokens(args.uid);
    }
}

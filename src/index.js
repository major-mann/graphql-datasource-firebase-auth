module.exports = createGraphqlFirebaseAuthSource;

const createGraphqlDatasource = require('@major-mann/graphql-datasource-base');
createGraphqlFirebaseAuthSource.graphql = createGraphqlDatasource.graphql;

async function createGraphqlFirebaseAuthSource({ auth, graphqlOptions }) {
    const definitions = createDefinitions();
    const source = await createGraphqlDatasource({ data: loadCollection, definitions, graphqlOptions });
    return source;

    function createDefinitions() {
        return [
            `
            type User {
                uid: ID!
                email: String
                emailVerified: Boolean
                phoneNumber: String
                disabled: Boolean
            }
            `
        ];
    }

    async function loadCollection() {
        return {
            find,
            list,
            create,
            upsert,
            update,
            delete: remove
        };

        async function create(id, data) {
            const user = await auth.createUser({
                uid: id,
                ...data
            });
            return user.uid;
        }

        async function upsert(id, data) {
            const user = await find(id);
            if (user) {
                await update(id, data);
            } else {
                await create(id, data);
            }
            return id;
        }

        async function update(id, data) {
            await auth.updateUser(id, data);
        }

        async function remove(id) {
            await auth.deleteUser(id);
        }

        async function find(id) {
            try {
                const user = await auth.getUser(id);
                return user;
            } catch (ex) {
                if (ex.code === 'auth/user-not-found') {
                    return undefined;
                } else {
                    throw ex;
                }
            }
        }

        async function list({ filter, order, cursor, limit }) {
            // TODO: We should be able to do something here...
            //  We could handle things like an email and phone number lookups
            //  The per item cursor would have to specify the page and an offset
            //  Would also be tricky to work with next and previous pages
            throw new Error('firebase auth does not support listing users');
        }
    }

}

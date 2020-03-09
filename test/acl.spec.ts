
const AccessControl = require('../src').AccessControl;

function type(o) {
    return Object.prototype.toString.call(o).match(/\s(\w+)/i)[1].toLowerCase();
}

function throwsAccessControlError(fn, errMsg?) {
    // expect(fn).toThrow();
    // try {
    //     fn();
    //     fail('should throw error');
    // } catch (err) {
    //     expect(err instanceof AccessControl.Error).toEqual(true);
    //     expect(AccessControl.isACError(err)).toEqual(true);
    //     if (errMsg) expect(err.message).toContain(errMsg);
    // }

    throwsError(fn, errMsg, AccessControl.Error.name);
}

async function promiseThrowsError(promise: Promise<any>, errMsg?) {
    try {
        await promise;
        fail('should throw error');
    } catch (err) {
        if (errMsg) expect(err.message).toContain(errMsg);
    }
}

function throwsError(fn, errMsg?, errName?) {
    expect(fn).toThrow();
    try {
        fn();
        fail('should throw error');
    } catch (err) {
        if (errName) expect(err.constructor.name).toEqual(errName);
        if (errMsg) expect(err.message).toContain(errMsg);
    }
}

describe('Test Suite: Access Control', function () {

    // grant list fetched from DB (to be converted to a valid grants object)
    let grantList = [
        { role: 'admin', resource: 'video', action: 'create', attributes: ['*'] },
        { role: 'admin', resource: 'video', action: 'read', attributes: ['*'] },
        { role: 'admin', resource: 'video', action: 'update', attributes: ['*'] },
        { role: 'admin', resource: 'video', action: 'delete', attributes: ['*'] },

        { role: 'user', resource: 'video', action: 'create', attributes: ['*'] },
        { role: 'user', resource: 'video', action: 'read', attributes: ['*'] },
        { role: 'user', resource: 'video', action: 'update', attributes: ['*'] },
        { role: 'user', resource: 'video', action: 'delete', attributes: ['*'] }
    ];


    // valid grants object
    let grantsObject = {
        admin: {
            grants: [
                {
                    resource: 'video', action: 'create'
                },
                {
                    resource: 'video', action: 'read'
                },
                {
                    resource: 'video', action: 'update'
                },
                {
                    resource: 'video', action: 'delete'
                }
            ]
        },
        user: {
            grants: [
                {
                    resource: 'video', action: 'create', attributes: ['*']
                },
                {
                    resource: 'video', action: 'read', attributes: ['*']
                },
                {
                    resource: 'video', action: 'update', attributes: ['*']
                },
                {
                    resource: 'video', action: 'delete', attributes: ['*']
                }
            ]
        }
    };

    let categorySportsCondition = { 'Fn': 'EQUALS', 'args': { 'category': 'sports' } };
    let categoryPoliticsCondition = { 'Fn': 'EQUALS', 'args': { 'category': 'politics' } };
    let categorySportsContext = { category: 'sports' };
    let categoryPoliticsContext = { category: 'politics' };
    let categoryCustomContextAllowed = { loginUserId: '1', resourceProfileId: '1' };
    let categoryCustomContextNotAllowed = { loginUserId: '1', resourceProfileId: '2' };

    let conditionalGrantList = [
        {
            role: 'sports/editor', resource: 'article', action: 'create', attributes: ['*'],
            condition: categorySportsCondition
        },
        {
            role: 'sports/editor', resource: 'article', action: 'update', attributes: ['*'],
            condition: categorySportsCondition

        },
        {
            role: 'sports/writer', resource: 'article', action: 'create', attributes: ['*', '!status'],
            condition: categorySportsCondition

        },
        {
            role: 'sports/writer', resource: 'article', action: 'update', attributes: ['*', '!status'],
            condition: categorySportsCondition
        }
    ];

    let conditionalGrantObject = {
        'sports/editor':
        {
            grants: [
                {
                    resource: 'article', action: 'create', attributes: ['*'],
                    condition: categorySportsCondition
                },
                {
                    resource: 'article', action: 'update', attributes: ['*'],
                    condition: categorySportsCondition
                }
            ]
        },
        'sports/writer': {
            grants: [{
                resource: 'article', action: 'create', attributes: ['*', '!status'],
                condition: categorySportsCondition
            },
            {
                resource: 'article', action: 'update', attributes: ['*', '!status'],
                condition: categorySportsCondition
            }]
        }
    };

    let conditionalGrantObjectWithCustomAsyncFunction = {
        'sports/custom':
        {
            grants: [
                {
                    resource: 'profile', action: ['create', 'edit'], attributes: ['*'],
                    condition: (context) => {
                        return new Promise((resolve) => {
                            setTimeout(() => {
                                resolve(context.loginUserId === context.resourceProfileId);
                            }, 200);
                        });
                    }
                }
            ]
        }
    };

    let conditionalGrantObjectWithCustomSyncFunction = {
        'sports/custom':
        {
            grants: [
                {
                    resource: 'profile', action: ['create', 'edit'], attributes: ['*'],
                    condition: (context) => {
                        return context.loginUserId === context.resourceProfileId;
                    }
                }
            ]
        }
    };

    let conditionalGrantArrayWithCustomAsyncFunction = [
        {
            role: 'sports/custom',
            resource: 'profile', action: ['create', 'edit'], attributes: ['*'],
            condition: (context) => {
                return new Promise((resolve) => {
                    setTimeout(() => {
                        resolve(context.loginUserId === context.resourceProfileId);
                    }, 200);
                });
            }
        }
    ];

    let conditionalGrantArrayWithCustomSyncFunction = [
        {
            role: 'sports/custom',
            resource: 'profile', action: ['create', 'edit'], attributes: ['*'],
            condition: (context) => {
                return context.loginUserId === context.resourceProfileId;
            }
        }
    ];

    beforeEach(function () {
        this.ac = new AccessControl();
    });

    // ----------------------------
    //  TESTS
    // ----------------------------

    it('should add grants from flat list (db), check/remove roles and resources', async function () {
        let ac = this.ac;
        ac.setGrants(grantList);
        // console.log("grants", ac.getGrants());
        // console.log("resources", ac.getResources());
        // console.log("roles", ac.getRoles());

        expect(ac.getRoles().length).toEqual(2);
        expect(ac.hasRole('admin')).toEqual(true);
        expect(ac.hasRole('user')).toEqual(true);
        expect(ac.hasRole('moderator')).toEqual(false);
        // removeRoles should also accept a string
        ac.removeRoles('admin');
        expect(ac.hasRole('admin')).toEqual(false);
        // no role named moderator but this should work
        ac.removeRoles(['user', 'moderator']);
        expect(ac.getRoles().length).toEqual(0);
    });



    it('should add conditional grants from flat list (db), check/remove roles and resources', async function () {
        let ac = this.ac;
        ac.setGrants(conditionalGrantList);
        // console.log("grants", ac.getGrants());
        // console.log("resources", ac.getResources());
        // console.log("roles", ac.getRoles());

        expect(ac.getRoles().length).toEqual(2);
        expect(ac.hasRole('sports/editor')).toEqual(true);
        expect(ac.hasRole('sports/writer')).toEqual(true);
        expect(ac.hasRole('sports/moderator')).toEqual(false);
        ac.removeRoles('sports/editor');
        expect(ac.hasRole('sports/editor')).toEqual(false);
        // no role named moderator but this should work
        ac.removeRoles(['sports/writer', 'moderator']);
        expect(ac.getRoles().length).toEqual(0);
    });

    it('should grant access and check permissions', async function () {
        const ac = this.ac;
        const attrs = ['*', '!size'];
        const conditionalAttrs = [{
            attributes: attrs,
            condition: undefined
        }];

        ac.grant('user').execute('create').on('photo', attrs);
        expect((await ac.can('user').execute('create').on('photo')).attributes).toEqual(attrs);

        // grant multiple roles the same permission for the same resource
        ac.grant(['user', 'admin']).execute('read').on('photo', attrs);
        expect((await ac.can('user').execute('read').on('photo')).granted).toEqual(true);
        expect((await ac.can('admin').execute('read').on('photo')).granted).toEqual(true);

        ac.grant('user').execute('update').on('photo', attrs);
        expect((await ac.can('user').execute('update').on('photo')).attributes).toEqual(attrs);


        ac.grant('user').execute('delete').on('photo', attrs);
        expect((await ac.can('user').execute('delete').on('photo')).attributes).toEqual(attrs);
    });

    it('should grant access and check permissions synchronously', function () {
        const ac = this.ac;
        const attrs = ['*', '!size'];

        ac.grant('user').execute('create').on('photo', attrs);
        expect((ac.can('user').execute('create').sync().on('photo')).attributes).toEqual(attrs);

        // grant multiple roles the same permission for the same resource
        ac.grant(['user', 'admin']).execute('read').on('photo', attrs);
        expect((ac.can('user').execute('read').sync().on('photo')).granted).toEqual(true);
        expect((ac.can('admin').execute('read').sync().on('photo')).granted).toEqual(true);

        ac.grant('user').execute('update').on('photo', attrs);
        expect((ac.can('user').execute('update').sync().on('photo')).attributes).toEqual(attrs);


        ac.grant('user').execute('delete').on('photo', attrs);
        expect((ac.can('user').execute('delete').sync().on('photo')).attributes).toEqual(attrs);
    });

    it('should grant access and check permissions for wildcard resources', async function () {
        const ac = this.ac;
        const attrs = ['*', '!size'];
        ac.grant('user1').execute('create').on('!photo', attrs);
        expect((await ac.can('user1').execute('create').on('photo')).granted).toEqual(false);
        expect((await ac.can('user1').execute('create').on('video')).granted).toEqual(true);
        ac.grant('user2').execute('create').on(['photo', 'video'], attrs);
        expect((await ac.can('user2').execute('create').on('photo')).granted).toEqual(true);
        expect((await ac.can('user2').execute('create').on('video')).granted).toEqual(true);
        ac.grant('user3').execute('create').on(['!photo'], attrs);
        expect((await ac.can('user3').execute('create').on('photo')).granted).toEqual(false);
        expect((await ac.can('user3').execute('create').on('video')).granted).toEqual(true);
    });

    it('should grant access and check permissions for wildcard resources synchronously', function () {
        const ac = this.ac;
        const attrs = ['*', '!size'];
        const conditionalAttrs = [{
            attributes: attrs,
            condition: undefined
        }];

        ac.grant('user1').execute('create').on('!photo', attrs);
        expect((ac.can('user1').execute('create').sync().on('photo')).granted).toEqual(false);
        expect((ac.can('user1').execute('create').sync().on('video')).granted).toEqual(true);
        ac.grant('user2').execute('create').on(['photo', 'video'], attrs);
        expect((ac.can('user2').execute('create').sync().on('photo')).granted).toEqual(true);
        expect((ac.can('user2').execute('create').sync().on('video')).granted).toEqual(true);
        ac.grant('user3').execute('create').on(['!photo'], attrs);
        expect((ac.can('user3').execute('create').sync().on('photo')).granted).toEqual(false);
        expect((ac.can('user3').execute('create').sync().on('video')).granted).toEqual(true);
    });

    it('should grant access and check permissions for wildcard actions', async function () {
        const ac = this.ac;
        const attrs = ['*', '!size'];
        const conditionalAttrs = [{
            attributes: attrs,
            condition: undefined
        }];

        ac.grant('user1').execute('!create').on('photo', attrs);
        expect((await ac.can('user1').execute('create').on('photo')).granted).toEqual(false);
        expect((await ac.can('user1').execute('update').on('photo')).granted).toEqual(true);

        ac.grant('user1').execute(['*', '!create']).on('photo', attrs);
        expect((await ac.can('user1').execute('create').on('photo')).granted).toEqual(false);
        expect((await ac.can('user1').execute('update').on('photo')).granted).toEqual(true);
        expect((await ac.can('user1').execute('update').on('photo')).granted).toEqual(true);

        ac.grant('user2').execute(['create', 'update']).on(['photo'], attrs);
        expect((await ac.can('user2').execute('update').on('photo')).granted).toEqual(true);
        expect((await ac.can('user2').execute('create').on('photo')).granted).toEqual(true);

        ac.grant('user3').execute(['*', '!create']).on(['photo'], attrs);
        expect((await ac.can('user3').execute('update').on('photo')).granted).toEqual(true);
        expect((await ac.can('user3').execute('create').on('photo')).granted).toEqual(false);
    });

    it('should grant access and check permissions for wildcard actions synchronously', function () {
        const ac = this.ac;
        const attrs = ['*', '!size'];

        ac.grant('user1').execute('!create').on('photo', attrs);
        expect((ac.can('user1').execute('create').sync().on('photo')).granted).toEqual(false);
        expect((ac.can('user1').execute('update').sync().on('photo')).granted).toEqual(true);

        ac.grant('user1').execute(['*', '!create']).on('photo', attrs);
        expect((ac.can('user1').execute('create').sync().on('photo')).granted).toEqual(false);
        expect((ac.can('user1').execute('update').sync().on('photo')).granted).toEqual(true);
        expect((ac.can('user1').execute('update').sync().on('photo')).granted).toEqual(true);

        ac.grant('user2').execute(['create', 'update']).on(['photo'], attrs);
        expect((ac.can('user2').execute('update').sync().on('photo')).granted).toEqual(true);
        expect((ac.can('user2').execute('create').sync().on('photo')).granted).toEqual(true);

        ac.grant('user3').execute(['*', '!create']).on(['photo'], attrs);
        expect((ac.can('user3').execute('update').sync().on('photo')).granted).toEqual(true);
        expect((ac.can('user3').execute('create').sync().on('photo')).granted).toEqual(false);
    });

    it('should filter object properties', async function () {
        expect(AccessControl.filter({ status: 'approved', id: 123 }, ['*', '!status'])).toEqual({ id: 123 });
        expect(AccessControl.filter({ status: 'approved', id: 123 }, ['*'])).toEqual({ status: 'approved', id: 123 });
    })

    it('should grant access with custom actions and check permissions', async function () {
        const ac = this.ac;
        const attrs = ['*', '!status'];
        const conditionalAttrs = [{
            attributes: attrs,
            condition: undefined
        }];

        ac.grant('editor').execute('publish').on('article', attrs);
        let permission = await ac.can('editor').execute('publish').on('article');
        expect(permission.attributes).toEqual(attrs);
        expect(await (permission.granted)).toEqual(true);

        ac.grant('sports/editor').execute('publish').when(categorySportsCondition).on('article', attrs);
        permission = await ac.can('sports/editor').execute('publish').with(categorySportsContext).on('article');
        expect(permission.attributes).toEqual(attrs);
        expect(permission.granted).toEqual(true);

        permission = await ac.can('sports/editor').execute('publish').with(categoryPoliticsContext).on('article');
        expect(permission.attributes).toEqual([]);
        expect(permission.granted).toEqual(false);

        ac.grant({
            role: 'politics/editor',
            action: 'publish',
            resource: 'article',
            condition: categoryPoliticsCondition,
            attributes: attrs
        });
        permission = await ac.can('politics/editor').execute('publish').with(categoryPoliticsContext).on('article');
        expect(permission.attributes).toEqual(attrs);
        expect(permission.granted).toEqual(true);

        // Simply set all the fields and call commit at the end
        ac.grant('user')
            .action('post')
            .resource('blog')
            .attributes(attrs)
            .condition({ Fn: 'EQUALS', args: { logged: true } })
            .commit();
        permission = await ac.can('user').execute('post').with({ logged: true }).on('blog');
        expect(permission.attributes).toEqual(attrs);
        expect(permission.granted).toEqual(true);
    });

    it('should grant access with custom actions and check permissions synchronously', function () {
        const ac = this.ac;
        const attrs = ['*', '!status'];
        const conditionalAttrs = [{
            attributes: attrs,
            condition: undefined
        }];

        ac.grant('editor').execute('publish').on('article', attrs);
        let permission = ac.can('editor').execute('publish').sync().on('article');
        expect(permission.attributes).toEqual(attrs);
        expect((permission.granted)).toEqual(true);

        ac.grant('sports/editor').execute('publish').when(categorySportsCondition).on('article', attrs);
        permission = ac.can('sports/editor').execute('publish').sync().with(categorySportsContext).on('article');
        expect(permission.attributes).toEqual(attrs);
        expect(permission.granted).toEqual(true);

        permission = ac.can('sports/editor').execute('publish').sync().with(categoryPoliticsContext).on('article');
        expect(permission.attributes).toEqual([]);
        expect(permission.granted).toEqual(false);

        ac.grant({
            role: 'politics/editor',
            action: 'publish',
            resource: 'article',
            condition: categoryPoliticsCondition,
            attributes: attrs
        });
        permission = ac.can('politics/editor').execute('publish').sync().with(categoryPoliticsContext).on('article');
        expect(permission.attributes).toEqual(attrs);
        expect(permission.granted).toEqual(true);

        // Simply set all the fields and call commit at the end
        ac.grant('user')
            .action('post')
            .resource('blog')
            .attributes(attrs)
            .condition({ Fn: 'EQUALS', args: { logged: true } })
            .commit();
        permission = ac.can('user').execute('post').sync().with({ logged: true }).on('blog');
        expect(permission.attributes).toEqual(attrs);
        expect(permission.granted).toEqual(true);
    });

    it('should grant access with OR condition and check permissions', async function () {
        const ac = this.ac;

        ac.grant('user').condition(
            {
                Fn: 'OR',
                args: [
                    categorySportsCondition,
                    categoryPoliticsCondition
                ]
            }).execute('create').on('article');
        expect((await ac.can('user').context(categorySportsContext).execute('create').on('article')).granted).toEqual(true);
        expect((await ac.can('user').context(categoryPoliticsContext).execute('create').on('article')).granted).toEqual(true);
        expect((await ac.can('user').context({ category: 'tech' }).execute('create').on('article')).granted).toEqual(false);

    });

    it('should grant access with OR condition and check permissions synchronously', function () {
        const ac = this.ac;

        ac.grant('user').condition(
            {
                Fn: 'OR',
                args: [
                    categorySportsCondition,
                    categoryPoliticsCondition
                ]
            }).execute('create').on('article');
        expect((ac.can('user').context(categorySportsContext).execute('create').sync().on('article')).granted).toEqual(true);
        expect((ac.can('user').context(categoryPoliticsContext).execute('create').sync().on('article')).granted).toEqual(true);
        expect((ac.can('user').context({ category: 'tech' }).execute('create').sync().on('article')).granted).toEqual(false);

    });



    it('should grant access with equals condition with list of values and check permissions ', async function () {
        const ac = this.ac;

        ac.grant('user').condition(
            {
                Fn: 'EQUALS',
                args: {
                    'category': ['sports', 'politics']
                }
            }).execute('create').on('article');
        expect((await ac.can('user').context(categorySportsContext).execute('create').on('article')).granted).toEqual(true);
        expect((await ac.can('user').context(categoryPoliticsContext).execute('create').on('article')).granted).toEqual(true);
        expect((await ac.can('user').context({ tag: 'tech' }).execute('create').on('article')).granted).toEqual(false);
    });

    it('should grant access with equals condition with list of values and check permissions synchronously', function () {
        const ac = this.ac;

        ac.grant('user').condition(
            {
                Fn: 'EQUALS',
                args: {
                    'category': ['sports', 'politics']
                }
            }).execute('create').on('article');
        expect((ac.can('user').context(categorySportsContext).execute('create').sync().on('article')).granted).toEqual(true);
        expect((ac.can('user').context(categoryPoliticsContext).execute('create').sync().on('article')).granted).toEqual(true);
        expect((ac.can('user').context({ tag: 'tech' }).execute('create').sync().on('article')).granted).toEqual(false);
    });

    it('should grant access with equals condition with single and check permissions', async function () {
        const ac = this.ac;

        ac.grant('user').condition(
            {
                Fn: 'EQUALS',
                args: {
                    'category': 'sports'
                }
            }).execute('create').on('article');
        expect((await ac.can('user').context(categorySportsContext).execute('create').on('article')).granted).toEqual(true);
        expect((await ac.can('user').context({ category: 'tech' }).execute('create').on('article')).granted).toEqual(false);
    });


    it('should grant access with equals condition with single and check permissions synchronously', function () {
        const ac = this.ac;

        ac.grant('user').condition(
            {
                Fn: 'EQUALS',
                args: {
                    'category': 'sports'
                }
            }).execute('create').on('article');
        expect((ac.can('user').context(categorySportsContext).execute('create').sync().on('article')).granted).toEqual(true);
        expect((ac.can('user').context({ category: 'tech' }).execute('create').sync().on('article')).granted).toEqual(false);
    });

    it('should grant access with not equals condition with list of values and check permissions', async function () {
        const ac = this.ac;

        ac.grant('user').condition(
            {
                Fn: 'NOT_EQUALS',
                args: {
                    'category': ['sports', 'politics']
                }
            }).execute('create').on('article');
        expect((await ac.can('user').context(categorySportsContext).execute('create').on('article')).granted).toEqual(false);
        expect((await ac.can('user').context(categoryPoliticsContext).execute('create').on('article')).granted).toEqual(false);
        expect((await ac.can('user').context({ category: 'tech' }).execute('create').on('article')).granted).toEqual(true);
    });

    it('should grant access with not equals condition with list of values and check permissions synchronously', function () {
        const ac = this.ac;

        ac.grant('user').condition(
            {
                Fn: 'NOT_EQUALS',
                args: {
                    'category': ['sports', 'politics']
                }
            }).execute('create').on('article');
        expect((ac.can('user').context(categorySportsContext).execute('create').sync().on('article')).granted).toEqual(false);
        expect((ac.can('user').context(categoryPoliticsContext).execute('create').sync().on('article')).granted).toEqual(false);
        expect((ac.can('user').context({ category: 'tech' }).execute('create').sync().on('article')).granted).toEqual(true);
    });


    it('should grant access with not equals condition with single value and check permissions', async function () {
        const ac = this.ac;

        ac.grant('user').condition(
            {
                Fn: 'NOT_EQUALS',
                args: {
                    'category': 'sports'
                }
            }).execute('create').on('article');
        expect((await ac.can('user').context(categorySportsContext).execute('create').on('article')).granted).toEqual(false);
        expect((await ac.can('user').context({ category: 'tech' }).execute('create').on('article')).granted).toEqual(true);
    });

    it('should grant access with not equals condition with single value and check permissions synchronously', function () {
        const ac = this.ac;

        ac.grant('user').condition(
            {
                Fn: 'NOT_EQUALS',
                args: {
                    'category': 'sports'
                }
            }).execute('create').on('article');
        expect((ac.can('user').context(categorySportsContext).execute('create').sync().on('article')).granted).toEqual(false);
        expect((ac.can('user').context({ category: 'tech' }).execute('create').sync().on('article')).granted).toEqual(true);
    });

    it('should grant access with and condition with list value and check permissions', async function () {
        const ac = this.ac;

        ac.grant('user').condition(
            {
                Fn: 'AND',
                args: [
                    {
                        Fn: 'NOT_EQUALS',
                        args: {
                            'category': 'sports'
                        }
                    },
                    {
                        Fn: 'NOT_EQUALS',
                        args: {
                            'category': 'politics'
                        }
                    }
                ]
            }).execute('create').on('article');
        expect((await ac.can('user').context(categorySportsContext).execute('create').on('article')).granted).toEqual(false);
        expect((await ac.can('user').context(categoryPoliticsContext).execute('create').on('article')).granted).toEqual(false);
        expect((await ac.can('user').context({ category: 'tech' }).execute('create').on('article')).granted).toEqual(true);
    });

    it('should grant access with and condition with list value and check permissions synchronously', function () {
        const ac = this.ac;

        ac.grant('user').condition(
            {
                Fn: 'AND',
                args: [
                    {
                        Fn: 'NOT_EQUALS',
                        args: {
                            'category': 'sports'
                        }
                    },
                    {
                        Fn: 'NOT_EQUALS',
                        args: {
                            'category': 'politics'
                        }
                    }
                ]
            }).execute('create').on('article');
        expect((ac.can('user').context(categorySportsContext).execute('create').sync().on('article')).granted).toEqual(false);
        expect((ac.can('user').context(categoryPoliticsContext).execute('create').sync().on('article')).granted).toEqual(false);
        expect((ac.can('user').context({ category: 'tech' }).execute('create').sync().on('article')).granted).toEqual(true);
    });

    it('should grant access with JSONPath context keys or values with EQUALS condition', async function () {
        const ac = this.ac;
        ac.grant('user').condition(
            {
                Fn: 'EQUALS',
                args: {
                    'requester': '$.owner'
                }
            }).execute('edit').on('article');
        expect((await ac.can('user').context({ owner: 'dilip', requester: 'dilip' })
            .execute('edit').on('article')).granted).toEqual(true);
        expect((await ac.can('user').context({ owner: 'tensult', requester: 'dilip' })
            .execute('edit').on('article')).granted).toEqual(false);

        ac.grant('user').condition(
                {
                    Fn: 'EQUALS',
                    args: {
                        '$.request.initiator': '$.owner'
                    }
                }).execute('edit').on('article');
            expect((await ac.can('user').context({ owner: 'dilip', request: {initiator: 'dilip' }})
                .execute('edit').on('article')).granted).toEqual(true);
            expect((await ac.can('user').context({ owner: 'tensult', request: {initiator: 'dilip' } })
                .execute('edit').on('article')).granted).toEqual(false);
    });

    it('should grant access with JSONPath context values with EQUALS condition synchronously', function () {
        const ac = this.ac;
        ac.grant('user').condition(
            {
                Fn: 'EQUALS',
                args: {
                    'requester': '$.owner'
                }
            }).execute('edit').on('article');
        expect((ac.can('user').context({ owner: 'dilip', requester: 'dilip' })
            .execute('edit').sync().on('article')).granted).toEqual(true);
        expect((ac.can('user').context({ owner: 'tensult', requester: 'dilip' })
            .execute('edit').sync().on('article')).granted).toEqual(false);
    });

    it('should grant access with JSONPath context values with NOT_EQUALS condition', async function () {
        const ac = this.ac;
        ac.grant('user').condition(
            {
                Fn: 'NOT_EQUALS',
                args: {
                    '$.requester': '$.owner'
                }
            }).execute('approve').on('article');
        expect((await ac.can('user').context({ owner: 'dilip', requester: 'dilip' })
            .execute('approve').on('article')).granted).toEqual(false);
        expect((await ac.can('user').context({ owner: 'tensult', requester: 'dilip' })
            .execute('approve').on('article')).granted).toEqual(true);
    });

    it('should grant access with JSONPath context values with NOT_EQUALS condition synchronously', function () {
        const ac = this.ac;
        ac.grant('user').condition(
            {
                Fn: 'NOT_EQUALS',
                args: {
                    '$.requester': '$.owner'
                }
            }).execute('approve').on('article');
        expect((ac.can('user').context({ owner: 'dilip', requester: 'dilip' })
            .execute('approve').sync().on('article')).granted).toEqual(false);
        expect((ac.can('user').context({ owner: 'tensult', requester: 'dilip' })
            .execute('approve').sync().on('article')).granted).toEqual(true);
    });

    it('should grant access with and with custom condition function', async function () {
        const ac = this.ac;

        ac.grant('user').condition((context) => {
            return context.category !== 'politics'
        }).execute('create').on('article');
        expect((await ac.can('user').context(categorySportsContext).execute('create').on('article')).granted).toEqual(true);
        expect((await ac.can('user').context(categoryPoliticsContext).execute('create').on('article')).granted).toEqual(false);
        expect((await ac.can('user').context({ category: 'tech' }).execute('create').on('article')).granted).toEqual(true);
    });

    it('should grant access with and with custom condition function synchronously', function () {
        const ac = this.ac;

        ac.grant('user').condition((context) => {
            return context.category !== 'politics'
        }).execute('create').on('article');
        expect((ac.can('user').context(categorySportsContext).execute('create').sync().on('article')).granted).toEqual(true);
        expect((ac.can('user').context(categoryPoliticsContext).execute('create').sync().on('article')).granted).toEqual(false);
        expect((ac.can('user').context({ category: 'tech' }).execute('create').sync().on('article')).granted).toEqual(true);
    });

    it('should grant access with and with async custom condition function', async function () {
        const ac = this.ac;

        ac.grant('user').condition((context) => {
            return new Promise((resolve) => {
                setTimeout(() => {
                    resolve(context.category !== 'politics');
                }, 200);
            });
        }).execute('create').on('article');
        expect((await ac.can('user').context(categorySportsContext).execute('create').on('article')).granted).toEqual(true);
        expect((await ac.can('user').context(categoryPoliticsContext).execute('create').on('article')).granted).toEqual(false);
        expect((await ac.can('user').context({ category: 'tech' }).execute('create').on('article')).granted).toEqual(true);
    });

    it('should fail when async custom condition used in sync', function () {
        const ac = this.ac;

        ac.grant('user').condition((context) => {
            return new Promise((resolve) => {
                setTimeout(() => {
                    resolve(context.category !== 'politics');
                }, 200);
            });
        }).execute('create').on('article');
        throwsAccessControlError(() => { ac.can('user').context(categorySportsContext).execute('create').sync().on('article') });
        throwsAccessControlError(() => { ac.can('user').context(categoryPoliticsContext).execute('create').sync().on('article') });
        throwsAccessControlError(() => { ac.can('user').context({ category: 'tech' }).execute('create').sync().on('article') });
    });

    it('should support initializing ACL when grants has custom functions', async function () {
        // Using object
        const acUsingObj = new AccessControl(conditionalGrantObjectWithCustomAsyncFunction);
        expect((await acUsingObj.can('sports/custom').context(categoryCustomContextAllowed)
            .execute('create').on('profile')).granted).toEqual(true);
        expect((await acUsingObj.can('sports/custom').context(categoryCustomContextNotAllowed)
            .execute('edit').on('profile')).granted).toEqual(false);

        // Using array
        const acUsingArray = new AccessControl(conditionalGrantArrayWithCustomAsyncFunction);
        expect((await acUsingArray.can('sports/custom').context(categoryCustomContextAllowed)
            .execute('create').on('profile')).granted).toEqual(true);
        expect((await acUsingArray.can('sports/custom').context(categoryCustomContextNotAllowed)
            .execute('edit').on('profile')).granted).toEqual(false);
    });

    it('should support initializing ACL when grants has custom functions synchronously', function () {
        // Using object
        const acUsingObj = new AccessControl(conditionalGrantObjectWithCustomSyncFunction);
        expect((acUsingObj.can('sports/custom').context(categoryCustomContextAllowed)
            .execute('create').sync().on('profile')).granted).toEqual(true);
        expect((acUsingObj.can('sports/custom').context(categoryCustomContextNotAllowed)
            .execute('edit').sync().on('profile')).granted).toEqual(false);

        // Using array
        const acUsingArray = new AccessControl(conditionalGrantArrayWithCustomSyncFunction);
        expect((acUsingArray.can('sports/custom').context(categoryCustomContextAllowed)
            .execute('create').sync().on('profile')).granted).toEqual(true);
        expect((acUsingArray.can('sports/custom').context(categoryCustomContextNotAllowed)
            .execute('edit').sync().on('profile')).granted).toEqual(false);
    });

    it('should stringfy and restore ACL with async custom condition function', async function () {
        const ac = this.ac;

        ac.grant('user').condition((context) => {
            return new Promise((resolve) => {
                setTimeout(() => {
                    resolve(context.category !== 'politics');
                }, 200);
            });
        }).execute('create').on('article');
        const newAC = AccessControl.fromJSON(ac.toJSON());
        expect(ac.toJSON()).toEqual(newAC.toJSON());
        expect((await newAC.can('user').context(categorySportsContext).execute('create').on('article')).granted).toEqual(true);
        expect((await newAC.can('user').context(categoryPoliticsContext).execute('create').on('article')).granted).toEqual(false);
        expect((await newAC.can('user').context({ category: 'tech' }).execute('create').on('article')).granted).toEqual(true);
    });

    it('should stringfy and restore ACL with sync custom condition function', function () {
        const ac = this.ac;

        ac.grant('user').condition((context) => {
            return context.category !== 'politics';
        }).execute('create').on('article');
        const newAC = AccessControl.fromJSON(ac.toJSON());
        expect(ac.toJSON()).toEqual(newAC.toJSON());
        expect((newAC.can('user').context(categorySportsContext).execute('create').sync().on('article')).granted).toEqual(true);
        expect((newAC.can('user').context(categoryPoliticsContext).execute('create').sync().on('article')).granted).toEqual(false);
        expect((newAC.can('user').context({ category: 'tech' }).execute('create').sync().on('article')).granted).toEqual(true);
    });

    it('should not grant access with and with async custom bad condition function', async function () {
        const ac = this.ac;

        ac.grant('user').condition((context) => {
            return new Promise((resolve, reject) => {
                setTimeout(() => {
                    reject('I am bad function');
                }, 200);
            });
        }).execute('create').on('article');

        await promiseThrowsError(ac.can('user').context(categorySportsContext).execute('create').on('article'));
    });

    it('should not grant access with and with sync custom bad condition function', function () {
        const ac = this.ac;

        ac.grant('user').condition((context) => {
            throw new Error('I am bad function');
        }).execute('create').on('article');

        throwsError(() => ac.can('user').context(categorySportsContext).execute('create').sync().on('article'));
    });

    it('should grant access with and condition with single value and check permissions', async function () {
        const ac = this.ac;

        ac.grant('user').condition(
            {
                Fn: 'AND',
                args: {
                    Fn: 'NOT_EQUALS',
                    args: {
                        'category': 'sports'
                    }
                }
            }).execute('create').on('article');
        expect((await ac.can('user').context(categorySportsContext).execute('create').on('article')).granted).toEqual(false);
        expect((await ac.can('user').context({ category: 'tech' }).execute('create').on('article')).granted).toEqual(true);
    });

    it('should grant access with and condition with single value and check permissions synchronously', function () {
        const ac = this.ac;

        ac.grant('user').condition(
            {
                Fn: 'AND',
                args: {
                    Fn: 'NOT_EQUALS',
                    args: {
                        'category': 'sports'
                    }
                }
            }).execute('create').on('article');
        expect((ac.can('user').context(categorySportsContext).execute('create').sync().on('article')).granted).toEqual(false);
        expect((ac.can('user').context({ category: 'tech' }).execute('create').sync().on('article')).granted).toEqual(true);
    });


    it('should grant access with not condition on list of values and check permissions', async function () {
        const ac = this.ac;

        ac.grant('user').condition(
            {
                Fn: 'NOT',
                args: [
                    {
                        Fn: 'EQUALS',
                        args: {
                            'category': 'sports'
                        }
                    },
                    {
                        Fn: 'EQUALS',
                        args: {
                            'category': 'politics'
                        }
                    }
                ]
            }).execute('create').on('article');
        expect((await ac.can('user').context(categorySportsContext).execute('create').on('article')).granted).toEqual(false);
        expect((await ac.can('user').context(categoryPoliticsContext).execute('create').on('article')).granted).toEqual(false);
        expect((await ac.can('user').context({ category: 'tech' }).execute('create').on('article')).granted).toEqual(true);
    });

    it('should grant access with not condition on list of values and check permissions synchronously', function () {
        const ac = this.ac;

        ac.grant('user').condition(
            {
                Fn: 'NOT',
                args: [
                    {
                        Fn: 'EQUALS',
                        args: {
                            'category': 'sports'
                        }
                    },
                    {
                        Fn: 'EQUALS',
                        args: {
                            'category': 'politics'
                        }
                    }
                ]
            }).execute('create').on('article');
        expect((ac.can('user').context(categorySportsContext).execute('create').sync().on('article')).granted).toEqual(false);
        expect((ac.can('user').context(categoryPoliticsContext).execute('create').sync().on('article')).granted).toEqual(false);
        expect((ac.can('user').context({ category: 'tech' }).execute('create').sync().on('article')).granted).toEqual(true);
    });

    it('should grant access with not condition on single value and check permissions', async function () {
        const ac = this.ac;

        ac.grant('user').condition(
            {
                Fn: 'NOT',
                args: {
                    Fn: 'EQUALS',
                    args: {
                        'category': 'sports'
                    }
                }
            }).execute('create').on('article');
        expect((await ac.can('user').context(categorySportsContext).execute('create').on('article')).granted).toEqual(false);
        expect((await ac.can('user').context({ category: 'tech' }).execute('create').on('article')).granted).toEqual(true);
    });

    it('should grant access with not condition on single value and check permissions synchronously', function () {
        const ac = this.ac;

        ac.grant('user').condition(
            {
                Fn: 'NOT',
                args: {
                    Fn: 'EQUALS',
                    args: {
                        'category': 'sports'
                    }
                }
            }).execute('create').on('article');
        expect((ac.can('user').context(categorySportsContext).execute('create').sync().on('article')).granted).toEqual(false);
        expect((ac.can('user').context({ category: 'tech' }).execute('create').sync().on('article')).granted).toEqual(true);
    });

    it('should grant access with list contains condition on single value and check permissions', async function () {
        const ac = this.ac;

        ac.grant('user').condition(
            {
                Fn: 'LIST_CONTAINS',
                args: {
                    tags: 'sports'
                }
            }).execute('create').on('article');
        expect((await ac.can('user').context({ tags: ['sports'] }).execute('create').on('article')).granted).toEqual(true);
        expect((await ac.can('user').context({ tags: ['politics'] }).execute('create').on('article')).granted).toEqual(false);
    });

    it('should grant access with list contains condition on single value and check permissions synchronously', function () {
        const ac = this.ac;

        ac.grant('user').condition(
            {
                Fn: 'LIST_CONTAINS',
                args: {
                    tags: 'sports'
                }
            }).execute('create').on('article');
        expect((ac.can('user').context({ tags: ['sports'] }).execute('create').sync().on('article')).granted).toEqual(true);
        expect((ac.can('user').context({ tags: ['politics'] }).execute('create').sync().on('article')).granted).toEqual(false);
    });

    it('should grant access with starts with condition on single value and check permissions', async function () {
        const ac = this.ac;

        ac.grant('user').condition(
            {
                Fn: 'STARTS_WITH',
                args: {
                    tags: 'sports'
                }
            }).execute('create').on('article');
        expect((await ac.can('user').context({ tags: 'sports' }).execute('create').on('article')).granted).toEqual(true);
        expect((await ac.can('user').context({ tags: 'politics' }).execute('create').on('article')).granted).toEqual(false);
    });

    it('should grant access with starts with condition on single value and check permissions synchronously', function () {
        const ac = this.ac;

        ac.grant('user').condition(
            {
                Fn: 'STARTS_WITH',
                args: {
                    tags: '$.category'
                }
            }).execute('create').on('article');
        expect((ac.can('user').context({ tags: 'sports', category: 'sports'  }).execute('create').sync().on('article')).granted).toEqual(true);
        expect((ac.can('user').context({ tags: 'politics' }).execute('create').sync().on('article')).granted).toEqual(false);
    });

    it('should grant access with starts with condition with list value and check permissions', async function () {
        const ac = this.ac;

        ac.grant('user').condition(
            {
                Fn: 'STARTS_WITH',
                args: {
                    tags: ['$.mainCategory', '$.subCategory']
                }
            }).execute('create').on('article');
        expect((await ac.can('user').context({ tags: 'sports', mainCategory: 'sports' }).execute('create').on('article')).granted).toEqual(true);
        expect((await ac.can('user').context({ tags: 'politics', subCategory: 'politics' }).execute('create').on('article')).granted).toEqual(true);
        expect((await ac.can('user').context({ tags: 'tech' }).execute('create').on('article')).granted).toEqual(false);
    });

    it('should grant access with starts with condition with list value and check permissions synchronously', function () {
        const ac = this.ac;

        ac.grant('user').condition(
            {
                Fn: 'STARTS_WITH',
                args: {
                    '$.tags': ['$.mainCategory', '$.subCategory']
                }
            }).execute('create').on('article');
        expect((ac.can('user').context({ tags: 'sports', mainCategory: 'sports' }).execute('create').sync().on('article')).granted).toEqual(true);
        expect((ac.can('user').context({ tags: 'politics', subCategory: 'politics' }).execute('create').sync().on('article')).granted).toEqual(true);
        expect((ac.can('user').context({ tags: 'tech' }).execute('create').sync().on('article')).granted).toEqual(false);
    });

    it('should grant access with list contains condition with multiple value and check permissions', async function () {
        const ac = this.ac;

        ac.grant('user').condition(
            {
                Fn: 'LIST_CONTAINS',
                args: {
                    '$.tags': ['sports', 'politics']
                }
            }).execute('create').on('article');
        expect((await ac.can('user').context({ tags: ['sports'] }).execute('create').on('article')).granted).toEqual(true);
        expect((await ac.can('user').context({ tags: ['politics'] }).execute('create').on('article')).granted).toEqual(true);
        expect((await ac.can('user').context({ tags: ['tech'] }).execute('create').on('article')).granted).toEqual(false);
    });

    it('should grant access with list contains condition with multiple value and check permissions synchronously', function () {
        const ac = this.ac;

        ac.grant('user').condition(
            {
                Fn: 'LIST_CONTAINS',
                args: {
                    tags: ['sports', 'politics']
                }
            }).execute('create').on('article');
        expect((ac.can('user').context({ tags: ['sports'] }).execute('create').sync().on('article')).granted).toEqual(true);
        expect((ac.can('user').context({ tags: ['politics'] }).execute('create').sync().on('article')).granted).toEqual(true);
        expect((ac.can('user').context({ tags: ['tech'] }).execute('create').sync().on('article')).granted).toEqual(false);
    });

    it('should grant access to attribute based on conditions', async function () {
        const ac = this.ac;
        const sportsAttrs = ['sportsField'];
        const politicsAttrs = ['politicsField'];

        ac.grant('user').condition(categorySportsCondition).execute('create').on('article', sportsAttrs);
        ac.grant('user').condition(categoryPoliticsCondition).attributes(politicsAttrs).execute('create').on('article');
        expect((await ac.can('user').context(categorySportsContext).execute('create').on('article')).granted).toEqual(true);
        expect((await ac.can('user').context(categorySportsContext).execute('create').on('article')).attributes).toEqual(sportsAttrs);
        expect((await ac.can('user').context(categoryPoliticsContext).execute('create').on('article')).granted).toEqual(true);
        expect((await ac.can('user').context(categoryPoliticsContext).execute('create').on('article')).attributes).toEqual(politicsAttrs);

    });

    it('should grant access to attribute based on conditions synchronously', function () {
        const ac = this.ac;
        const sportsAttrs = ['sportsField'];
        const politicsAttrs = ['politicsField'];

        ac.grant('user').condition(categorySportsCondition).execute('create').on('article', sportsAttrs);
        ac.grant('user').condition(categoryPoliticsCondition).attributes(politicsAttrs).execute('create').on('article');
        expect((ac.can('user').context(categorySportsContext).execute('create').sync().on('article')).granted).toEqual(true);
        expect((ac.can('user').context(categorySportsContext).execute('create').sync().on('article')).attributes).toEqual(sportsAttrs);
        expect((ac.can('user').context(categoryPoliticsContext).execute('create').sync().on('article')).granted).toEqual(true);
        expect((ac.can('user').context(categoryPoliticsContext).execute('create').sync().on('article')).attributes).toEqual(politicsAttrs);

    });

    it('should add conditional grants with list and check permissions', async function () {
        const ac = this.ac;
        ac.setGrants(conditionalGrantList);
        const editorAttrs = ['*'];
        const writerAttrs = ['*', '!status'];
        expect((await ac.can('sports/editor').context(categorySportsContext).execute('create').on('article')).attributes).toEqual(editorAttrs);
        expect((await ac.can('sports/editor').context(categoryPoliticsContext).execute('update').on('article')).granted).toEqual(false);
        expect((await ac.can('sports/writer').context(categorySportsContext).execute('create').on('article')).attributes).toEqual(writerAttrs);
        expect((await ac.can('sports/writer').context(categoryPoliticsContext).execute('update').on('article')).granted).toEqual(false);
        // should fail when context is not passed
        expect((await ac.can('sports/writer').execute('create').on('article')).granted).toEqual(false);
    });

    it('should add conditional grants with list and check permissions synchronously', function () {
        const ac = this.ac;
        ac.setGrants(conditionalGrantList);
        const editorAttrs = ['*'];
        const writerAttrs = ['*', '!status'];
        expect((ac.can('sports/editor').context(categorySportsContext).execute('create').sync().on('article')).attributes).toEqual(editorAttrs);
        expect((ac.can('sports/editor').context(categoryPoliticsContext).execute('update').sync().on('article')).granted).toEqual(false);
        expect((ac.can('sports/writer').context(categorySportsContext).execute('create').sync().on('article')).attributes).toEqual(writerAttrs);
        expect((ac.can('sports/writer').context(categoryPoliticsContext).execute('update').sync().on('article')).granted).toEqual(false);
        // should fail when context is not passed
        expect((ac.can('sports/writer').execute('create').sync().on('article')).granted).toEqual(false);
    });

    it('should chain grant methods and check permissions', async function () {
        let ac = this.ac,
            attrs = ['*'];

        ac.grant('superadmin')
            .execute('create').on('profile', attrs)
            .execute('read').on('profile', attrs)
            .execute('create').on('video', []) // no attributes allowed
            .execute('create').on('photo'); // all attributes allowed

        expect((await ac.can('superadmin').execute('create').on('profile')).granted).toEqual(true);
        expect((await ac.can('superadmin').execute('read').on('profile')).granted).toEqual(true);
        expect((await ac.can('superadmin').execute('create').on('video')).granted).toEqual(false);
        expect((await ac.can('superadmin').execute('create').on('photo')).granted).toEqual(true);
    });

    it('should chain grant methods and check permissions synchronously', function () {
        let ac = this.ac,
            attrs = ['*'];

        ac.grant('superadmin')
            .execute('create').on('profile', attrs)
            .execute('read').on('profile', attrs)
            .execute('create').on('video', []) // no attributes allowed
            .execute('create').on('photo'); // all attributes allowed

        expect((ac.can('superadmin').execute('create').sync().on('profile')).granted).toEqual(true);
        expect((ac.can('superadmin').execute('read').sync().on('profile')).granted).toEqual(true);
        expect((ac.can('superadmin').execute('create').sync().on('video')).granted).toEqual(false);
        expect((ac.can('superadmin').execute('create').sync().on('photo')).granted).toEqual(true);
    });

    it('should grant access via object and check permissions', async function () {
        let ac = this.ac,
            attrs = ['*'];

        let o1 = {
            role: 'moderator',
            resource: 'post',
            action: 'create', // action
            attributes: ['*'] // grant only
        };
        let o2 = {
            role: 'moderator',
            resource: 'news',
            action: 'read', // separate action
            attributes: ['*'] // grant only
        };
        let o3 = {
            role: 'moderator',
            resource: 'book',
            // no action set
            attributes: ['*'] // grant only
        };

        ac.grant(o1).grant(o2);
        ac.grant(o3).execute('update').on();

        expect((await ac.can('moderator').execute('create').on('post')).granted).toEqual(true);
        expect((await ac.can('moderator').execute('read').on('news')).granted).toEqual(true);
        expect((await ac.can('moderator').execute('update').on('book')).granted).toEqual(true);


        // should overwrite already defined action in o1 object
        ac.grant(o1).execute('read').on();
        expect((await ac.can('moderator').execute('read').on('post')).granted).toEqual(true);

        // non-set action (update:own)
        expect((await ac.can('moderator').execute('update').on('news')).granted).toEqual(false);
        // non-existent resource
        expect((await ac.can('moderator').execute('create').on('foo')).granted).toEqual(false);
    });

    it('should grant access via object and check permissions synchronously', function () {
        let ac = this.ac,
            attrs = ['*'];

        let o1 = {
            role: 'moderator',
            resource: 'post',
            action: 'create', // action
            attributes: ['*'] // grant only
        };
        let o2 = {
            role: 'moderator',
            resource: 'news',
            action: 'read', // separate action
            attributes: ['*'] // grant only
        };
        let o3 = {
            role: 'moderator',
            resource: 'book',
            // no action set
            attributes: ['*'] // grant only
        };

        ac.grant(o1).grant(o2);
        ac.grant(o3).execute('update').on();

        expect((ac.can('moderator').execute('create').sync().on('post')).granted).toEqual(true);
        expect((ac.can('moderator').execute('read').sync().on('news')).granted).toEqual(true);
        expect((ac.can('moderator').execute('update').sync().on('book')).granted).toEqual(true);


        // should overwrite already defined action in o1 object
        ac.grant(o1).execute('read').on();
        expect((ac.can('moderator').execute('read').sync().on('post')).granted).toEqual(true);

        // non-set action (update:own)
        expect((ac.can('moderator').execute('update').sync().on('news')).granted).toEqual(false);
        // non-existent resource
        expect((ac.can('moderator').execute('create').sync().on('foo')).granted).toEqual(false);
    });

    it('should grant conditional access via object and check permissions', async function () {
        let ac = this.ac,
            attrs = ['*'];

        let o1 = {
            role: 'moderator',
            resource: 'post',
            action: 'create', // action
            attributes: ['*'], // grant only
            condition: categorySportsCondition
        };
        let o2 = {
            role: 'moderator',
            resource: 'news',
            action: 'read', // separate action
            attributes: ['*'], // grant only,
            condition: categorySportsCondition
        };
        let o3 = {
            role: 'moderator',
            resource: 'book',
            // no action set
            attributes: ['*'] // grant only
        };

        ac.grant(o1).grant(o2);
        ac.grant(o3).execute('update').on();

        expect((await ac.can('moderator').context(categorySportsContext).execute('create').on('post')).granted).toEqual(true);
        expect((await ac.can('moderator').context(categorySportsContext).execute('read').on('news')).granted).toEqual(true);
        expect((await ac.can('moderator').context(categorySportsContext).execute('update').on('book')).granted).toEqual(true);


        // should overwrite already defined action in o1 object
        ac.grant(o1).execute('read').on();
        expect((await ac.can('moderator').context(categorySportsContext).execute('read').on('post')).granted).toEqual(true);

        // non-set action (update:own)
        expect((await ac.can('moderator').context(categorySportsContext).execute('update').on('news')).granted).toEqual(false);
        // non-existent resource
        expect((await ac.can('moderator').context(categorySportsContext).execute('create').on('foo')).granted).toEqual(false);
    });

    it('should grant conditional access via object and check permissions synchronously', function () {
        let ac = this.ac,
            attrs = ['*'];

        let o1 = {
            role: 'moderator',
            resource: 'post',
            action: 'create', // action
            attributes: ['*'], // grant only
            condition: categorySportsCondition
        };
        let o2 = {
            role: 'moderator',
            resource: 'news',
            action: 'read', // separate action
            attributes: ['*'], // grant only,
            condition: categorySportsCondition
        };
        let o3 = {
            role: 'moderator',
            resource: 'book',
            // no action set
            attributes: ['*'] // grant only
        };

        ac.grant(o1).grant(o2);
        ac.grant(o3).execute('update').on();

        expect((ac.can('moderator').context(categorySportsContext).execute('create').sync().on('post')).granted).toEqual(true);
        expect((ac.can('moderator').context(categorySportsContext).execute('read').sync().on('news')).granted).toEqual(true);
        expect((ac.can('moderator').context(categorySportsContext).execute('update').sync().on('book')).granted).toEqual(true);


        // should overwrite already defined action in o1 object
        ac.grant(o1).execute('read').on();
        expect((ac.can('moderator').context(categorySportsContext).execute('read').sync().on('post')).granted).toEqual(true);

        // non-set action (update:own)
        expect((ac.can('moderator').context(categorySportsContext).execute('update').sync().on('news')).granted).toEqual(false);
        // non-existent resource
        expect((ac.can('moderator').context(categorySportsContext).execute('create').sync().on('foo')).granted).toEqual(false);
    });

    it('should skip conditions when skipConditions is used', async function () {
        let ac = this.ac;
        ac.grant('user').condition(categorySportsCondition).execute('create').on('article');
        expect((await ac.permission({
            role: 'user', action: 'create', resource: 'article', context: categorySportsContext
        })).granted).toEqual(true);
        expect((await ac.can('user').execute('create').with(categorySportsContext).on('article')).granted).toEqual(true);
        expect((await ac.can('user').execute('create').on('article', true)).granted).toEqual(true); // conditions skipped
        expect((await ac.can('user').execute('create').on('article', false)).granted).toEqual(false); // context not set
        expect((await ac.can('user').execute('create').on('article')).granted).toEqual(false); // context not set
        expect((await ac.permission({ role: 'user', action: 'create', resource: 'article' })).granted).toEqual(false); // context not set
        // context not set and conditions skipped
        expect((await ac.permission({ role: 'user', action: 'create', resource: 'article', skipConditions: true })).granted).toEqual(true);
    });

    it('should skip conditions when skipConditions is used synchronously', function () {
        let ac = this.ac;
        ac.grant('user').condition(categorySportsCondition).execute('create').on('article');
        expect((ac.permissionSync({
            role: 'user', action: 'create', resource: 'article', context: categorySportsContext
        })).granted).toEqual(true);
        expect((ac.can('user').execute('create').with(categorySportsContext).sync().on('article')).granted).toEqual(true);
        expect((ac.can('user').execute('create').sync().on('article', true)).granted).toEqual(true); // conditions skipped
        expect((ac.can('user').execute('create').sync().on('article', false)).granted).toEqual(false); // context not set
        expect((ac.can('user').execute('create').sync().on('article')).granted).toEqual(false); // context not set
        expect((ac.permissionSync({ role: 'user', action: 'create', resource: 'article' })).granted).toEqual(false); // context not set
        // context not set and conditions skipped
        expect((ac.permissionSync({ role: 'user', action: 'create', resource: 'article', skipConditions: true })).granted).toEqual(true);
    });

    it('should return allowed resources for given roles', async function () {
        let ac = this.ac;
        ac.grant('user').condition(categorySportsCondition).execute('create').on('article');
        ac.grant('user').execute('*').on('image');
        ac.extendRole('admin', 'user');
        ac.grant('admin').execute('*').on('category');
        ac.extendRole('owner', 'admin');
        ac.grant('owner').execute('*').on('video');

        expect((await ac.allowedResources({ role: 'user' })).sort()).toEqual(['article', 'image']);
        expect((await ac.allowedResources({ role: 'user', context: categorySportsContext })).sort()).toEqual(['article', 'image']);
        expect((await ac.allowedResources({ role: 'user', context: categoryPoliticsContext })).sort()).toEqual(['image']);
        expect((await ac.allowedResources({ role: 'admin' })).sort()).toEqual(['article', 'category', 'image']);
        expect((await ac.allowedResources({ role: 'owner' })).sort()).toEqual(['article', 'category', 'image', 'video']);
        expect((await ac.allowedResources({ role: ['admin', 'owner'] })).sort()).toEqual(['article', 'category', 'image', 'video']);
    });

    it('should return allowed resources for given roles synchronously', function () {
        let ac = this.ac;
        ac.grant('user').condition(categorySportsCondition).execute('create').on('article');
        ac.grant('user').execute('*').on('image');
        ac.extendRole('admin', 'user');
        ac.grant('admin').execute('*').on('category');
        ac.extendRole('owner', 'admin');
        ac.grant('owner').execute('*').on('video');

        expect((ac.allowedResourcesSync({ role: 'user' })).sort()).toEqual(['article', 'image']);
        expect((ac.allowedResourcesSync({ role: 'user', context: categorySportsContext })).sort()).toEqual(['article', 'image']);
        expect((ac.allowedResourcesSync({ role: 'user', context: categoryPoliticsContext })).sort()).toEqual(['image']);
        expect((ac.allowedResourcesSync({ role: 'admin' })).sort()).toEqual(['article', 'category', 'image']);
        expect((ac.allowedResourcesSync({ role: 'owner' })).sort()).toEqual(['article', 'category', 'image', 'video']);
        expect((ac.allowedResourcesSync({ role: ['admin', 'owner'] })).sort()).toEqual(['article', 'category', 'image', 'video']);
    });

    it('should return allowed actions for given roles and resource', async function () {
        let ac = this.ac;
        ac.grant('user').condition(categorySportsCondition).execute('create').on('article');
        ac.grant('user').execute('*').on('image');
        ac.extendRole('admin', 'user');
        ac.grant('admin').execute('delete').on('article');
        ac.grant('admin').execute('*').on('category');
        ac.extendRole('owner', 'admin');
        ac.grant('owner').execute('*').on('video');

        expect((await ac.allowedActions({ role: 'user', resource: 'article' })).sort()).toEqual(['create']);
        expect((await ac.allowedActions({ role: 'user', resource: 'article', context: categorySportsContext })).sort()).toEqual(['create']);
        expect((await ac.allowedActions({ role: 'user', resource: 'article', context: categoryPoliticsContext }))).toEqual([]);
        expect((await ac.allowedActions({ role: ['admin', 'user'], resource: 'article' })).sort()).toEqual(['create', 'delete']);

        expect((await ac.allowedActions({ role: 'admin', resource: 'category' })).sort()).toEqual(['*']);
        expect((await ac.allowedActions({ role: 'owner', resource: 'video' })).sort()).toEqual(['*']);
    });

    it('should return allowed actions for given roles and resource synchronously', function () {
        let ac = this.ac;
        ac.grant('user').condition(categorySportsCondition).execute('create').on('article');
        ac.grant('user').execute('*').on('image');
        ac.extendRole('admin', 'user');
        ac.grant('admin').execute('delete').on('article');
        ac.grant('admin').execute('*').on('category');
        ac.extendRole('owner', 'admin');
        ac.grant('owner').execute('*').on('video');

        expect((ac.allowedActionsSync({ role: 'user', resource: 'article' })).sort()).toEqual(['create']);
        expect((ac.allowedActionsSync({ role: 'user', resource: 'article', context: categorySportsContext })).sort()).toEqual(['create']);
        expect((ac.allowedActionsSync({ role: 'user', resource: 'article', context: categoryPoliticsContext }))).toEqual([]);
        expect((ac.allowedActionsSync({ role: ['admin', 'user'], resource: 'article' })).sort()).toEqual(['create', 'delete']);

        expect((ac.allowedActionsSync({ role: 'admin', resource: 'category' })).sort()).toEqual(['*']);
        expect((ac.allowedActionsSync({ role: 'owner', resource: 'video' })).sort()).toEqual(['*']);
    });


    it('should return allowing roles for given permission', async function () {
        let ac = this.ac;
        ac.setGrants(conditionalGrantObject);
        ac.grant('user').condition(categorySportsCondition).execute('create').on('blog');
        ac.grant('user').execute('*').on('image');
        ac.extendRole('sports/editor', 'user');
        ac.extendRole('admin', 'user');
        ac.grant('admin').execute('*').on('category');
        ac.extendRole('owner', 'admin');
        ac.grant('owner').execute('*').on('video');
        ac.grant('owner').execute('*').on('role');

        expect((await ac.allowingRoles({ resource: 'image', action: 'create' })).sort()).toEqual(['admin', 'owner', 'sports/editor', 'user']);
        expect((await ac.allowingRoles({ resource: 'video', action: 'create' })).sort()).toEqual(['owner']);
        expect((await ac.allowingRoles({ resource: 'category', action: 'create' })).sort()).toEqual(['admin', 'owner']);
        expect((await ac.allowingRoles({ resource: 'blog', action: 'create' }))).toEqual([]);
        expect((await ac.allowingRoles({ resource: 'blog', action: 'create', context: categoryPoliticsContext }))).toEqual([]);
        expect((await ac.allowingRoles({
            resource: 'blog',
            action: 'create',
            context: categorySportsContext
        })).sort()).toEqual(['admin', 'owner', 'sports/editor', 'user']);
        expect((await ac.allowingRoles({
            resource: 'article',
            action: 'create',
            context: categorySportsContext
        })).sort()).toEqual(['sports/editor', 'sports/writer']);

        // should adjust permissions when role is removed
        ac.removeRoles('user');
        expect((await ac.allowingRoles({
            resource: 'blog',
            action: 'create',
            context: categorySportsContext
        })).sort()).toEqual([]);
    });

    it('should return allowing roles for given permission synchronously', function () {
        let ac = this.ac;
        ac.setGrants(conditionalGrantObject);
        ac.grant('user').condition(categorySportsCondition).execute('create').on('blog');
        ac.grant('user').execute('*').on('image');
        ac.extendRole('sports/editor', 'user');
        ac.extendRole('admin', 'user');
        ac.grant('admin').execute('*').on('category');
        ac.extendRole('owner', 'admin');
        ac.grant('owner').execute('*').on('video');
        ac.grant('owner').execute('*').on('role');

        expect((ac.allowingRolesSync({ resource: 'image', action: 'create' })).sort()).toEqual(['admin', 'owner', 'sports/editor', 'user']);
        expect((ac.allowingRolesSync({ resource: 'video', action: 'create' })).sort()).toEqual(['owner']);
        expect((ac.allowingRolesSync({ resource: 'category', action: 'create' })).sort()).toEqual(['admin', 'owner']);
        expect((ac.allowingRolesSync({ resource: 'blog', action: 'create' }))).toEqual([]);
        expect((ac.allowingRolesSync({ resource: 'blog', action: 'create', context: categoryPoliticsContext }))).toEqual([]);
        expect((ac.allowingRolesSync({
            resource: 'blog',
            action: 'create',
            context: categorySportsContext
        })).sort()).toEqual(['admin', 'owner', 'sports/editor', 'user']);
        expect((ac.allowingRolesSync({
            resource: 'article',
            action: 'create',
            context: categorySportsContext
        })).sort()).toEqual(['sports/editor', 'sports/writer']);

        // should adjust permissions when role is removed
        ac.removeRoles('user');
        expect((ac.allowingRolesSync({
            resource: 'blog',
            action: 'create',
            context: categorySportsContext
        })).sort()).toEqual([]);
    });

    it('should grant access (variation, chained)', async function () {
        let ac = this.ac;
        ac.setGrants(grantsObject);

        expect((await ac.can('admin').execute('create').on('video')).granted).toEqual(true);

        ac.grant('foo').execute('create').on('bar');
        expect((await ac.can('foo').execute('create').on('bar')).granted).toEqual(true);

        ac.grant('foo').execute('create').on('baz', []); // no attributes, actually denied instead of granted
        expect((await ac.can('foo').execute('create').on('baz')).granted).toEqual(false);

        ac.grant('qux')
            .execute('create').on('resource1')
            .execute('update').on('resource2')
            .execute('read').on('resource1')
            .execute('delete').on('resource1', []);
        expect((await ac.can('qux').execute('create').on('resource1')).granted).toEqual(true);
        expect((await ac.can('qux').execute('update').on('resource2')).granted).toEqual(true);
        expect((await ac.can('qux').execute('read').on('resource1')).granted).toEqual(true);
        expect((await ac.can('qux').execute('delete').on('resource1')).granted).toEqual(false);

        ac.grant('editor').resource('file1').execute('update').on();
        ac.grant().role('editor').execute('update').on('file2');
        ac.grant().role('editor').resource('file3').execute('update').on();
        expect((await ac.can('editor').execute('update').on('file1')).granted).toEqual(true);
        expect((await ac.can('editor').execute('update').on('file2')).granted).toEqual(true);
        expect((await ac.can('editor').execute('update').on('file3')).granted).toEqual(true);

        ac.grant('editor')
            .resource('fileX').execute('read').on().execute('create').on()
            .resource('fileY').execute('update').on().execute('delete').on();
        expect((await ac.can('editor').execute('read').on('fileX')).granted).toEqual(true);
        expect((await ac.can('editor').execute('create').on('fileX')).granted).toEqual(true);
        expect((await ac.can('editor').execute('update').on('fileY')).granted).toEqual(true);
        expect((await ac.can('editor').execute('delete').on('fileY')).granted).toEqual(true);

    });

    it('should grant access (variation, chained) synchronously', function () {
        let ac = this.ac;
        ac.setGrants(grantsObject);

        expect((ac.can('admin').execute('create').sync().on('video')).granted).toEqual(true);

        ac.grant('foo').execute('create').on('bar');
        expect((ac.can('foo').execute('create').sync().on('bar')).granted).toEqual(true);

        ac.grant('foo').execute('create').on('baz', []); // no attributes, actually denied instead of granted
        expect((ac.can('foo').execute('create').sync().on('baz')).granted).toEqual(false);

        ac.grant('qux')
            .execute('create').on('resource1')
            .execute('update').on('resource2')
            .execute('read').on('resource1')
            .execute('delete').on('resource1', []);
        expect((ac.can('qux').execute('create').sync().on('resource1')).granted).toEqual(true);
        expect((ac.can('qux').execute('update').sync().on('resource2')).granted).toEqual(true);
        expect((ac.can('qux').execute('read').sync().on('resource1')).granted).toEqual(true);
        expect((ac.can('qux').execute('delete').sync().on('resource1')).granted).toEqual(false);

        ac.grant('editor').resource('file1').execute('update').on();
        ac.grant().role('editor').execute('update').on('file2');
        ac.grant().role('editor').resource('file3').execute('update').on();
        expect((ac.can('editor').execute('update').sync().on('file1')).granted).toEqual(true);
        expect((ac.can('editor').execute('update').sync().on('file2')).granted).toEqual(true);
        expect((ac.can('editor').execute('update').sync().on('file3')).granted).toEqual(true);

        ac.grant('editor')
            .resource('fileX').execute('read').on().execute('create').on()
            .resource('fileY').execute('update').on().execute('delete').on();
        expect((ac.can('editor').execute('read').sync().on('fileX')).granted).toEqual(true);
        expect((ac.can('editor').execute('create').sync().on('fileX')).granted).toEqual(true);
        expect((ac.can('editor').execute('update').sync().on('fileY')).granted).toEqual(true);
        expect((ac.can('editor').execute('delete').sync().on('fileY')).granted).toEqual(true);

    });

    it('should switch-chain grant roles', async function () {
        let ac = this.ac;
        ac.grant('r1')
            .execute('create').on('a')
            .grant('r2')
            .execute('create').on('b')
            .execute('read').on('b')
            .grant('r1')
            .execute('update').on('c')

        expect((await ac.can('r1').execute('create').on('a')).granted).toEqual(true);
        expect((await ac.can('r1').execute('update').on('c')).granted).toEqual(true);
        expect((await ac.can('r2').execute('create').on('b')).granted).toEqual(true);
        expect((await ac.can('r2').execute('read').on('b')).granted).toEqual(true);
    });

    it('should switch-chain grant roles synchronously', function () {
        let ac = this.ac;
        ac.grant('r1')
            .execute('create').on('a')
            .grant('r2')
            .execute('create').on('b')
            .execute('read').on('b')
            .grant('r1')
            .execute('update').on('c')

        expect((ac.can('r1').execute('create').sync().on('a')).granted).toEqual(true);
        expect((ac.can('r1').execute('update').sync().on('c')).granted).toEqual(true);
        expect((ac.can('r2').execute('create').sync().on('b')).granted).toEqual(true);
        expect((ac.can('r2').execute('read').sync().on('b')).granted).toEqual(true);
    });

    it('should grant comma/semi-colon separated roles', async function () {
        let ac = this.ac;
        // also supporting comma/semi-colon separated roles
        ac.grant('role2; role3, editor; viewer, agent').execute('create').on('book');
        expect(ac.hasRole('role3')).toEqual(true);
        expect(ac.hasRole('editor')).toEqual(true);
        expect(ac.hasRole('agent')).toEqual(true);
    });

    it('permission should also return queried role(s) and resource', async function () {
        let ac = this.ac;
        // also supporting comma/semi-colon separated roles
        ac.grant('foo, bar').execute('create').on('baz');
        expect((await ac.can('bar').execute('create').on('baz')).granted).toEqual(true);
        // returned permission should provide queried role(s) as array
        expect((await ac.can('foo').execute('create').on('baz')).roles).toContain('foo');
        // returned permission should provide queried resource
        expect((await ac.can('foo').execute('create').on('baz')).resource).toEqual('baz');
        // create is execute("create").on. but above only returns the queried value, not the result.
    });

    it('permission should also return queried role(s) and resource synchronously', function () {
        let ac = this.ac;
        // also supporting comma/semi-colon separated roles
        ac.grant('foo, bar').execute('create').on('baz');
        expect((ac.can('bar').execute('create').sync().on('baz')).granted).toEqual(true);
        // returned permission should provide queried role(s) as array
        expect((ac.can('foo').execute('create').sync().on('baz')).roles).toContain('foo');
        // returned permission should provide queried resource
        expect((ac.can('foo').execute('create').sync().on('baz')).resource).toEqual('baz');
        // create is execute("create").on. but above only returns the queried value, not the result.
    });

    it('should extend / remove roles', async function () {
        let ac = this.ac;

        ac.grant('admin').execute('create').on('book');
        ac.extendRole('onur', 'admin');
        expect(ac.getGrants().onur.$extend['admin']).toEqual({ condition: undefined });

        ac.grant('role2, role3, editor, viewer, agent').execute('create').on('book');

        ac.extendRole('onur', ['role2', 'role3']);
        expect(Object.keys(ac.getGrants().onur.$extend).sort()).toEqual(['admin', 'role2', 'role3']);

        await ac.grant('admin').extend('editor');
        expect(Object.keys(ac.getGrants().admin.$extend)).toEqual(['editor']);
        (await ac.grant('admin').extend(['viewer', 'editor', 'agent'])).execute('read').on('video');
        expect(Object.keys(ac.getGrants().admin.$extend).sort()).toEqual(['agent', 'editor', 'viewer']);
        (await ac.grant(['editor', 'agent']).extend(['role2', 'role3'])).execute('update').on('photo');
        expect(Object.keys(ac.getGrants().editor.$extend).sort()).toEqual(['role2', 'role3']);

        ac.removeRoles(['editor', 'agent']);
        expect(ac.getGrants().editor).toBeUndefined();
        expect(ac.getGrants().agent).toBeUndefined();
        expect(ac.getGrants().admin.$extend['editor']).toBeUndefined();
        expect(ac.getGrants().admin.$extend['agent']).toBeUndefined();
        throwsAccessControlError(() => ac.grant('roleX').extend('roleX'));
        throwsAccessControlError(() =>ac.grant(['admin2', 'roleX']).extend(['roleX', 'admin3']));
    });

    it('should extend / remove roles synchronously', function () {
        let ac = this.ac;

        ac.grant('admin').execute('create').on('book');
        ac.extendRole('onur', 'admin');
        expect(ac.getGrants().onur.$extend['admin']).toEqual({ condition: undefined });

        ac.grant('role2, role3, editor, viewer, agent').execute('create').on('book');

        ac.extendRole('onur', ['role2', 'role3']);
        expect(Object.keys(ac.getGrants().onur.$extend).sort()).toEqual(['admin', 'role2', 'role3']);

        ac.grant('admin').extendSync('editor');
        expect(Object.keys(ac.getGrants().admin.$extend)).toEqual(['editor']);
        (ac.grant('admin').extendSync(['viewer', 'editor', 'agent'])).execute('read').on('video');
        expect(Object.keys(ac.getGrants().admin.$extend).sort()).toEqual(['agent', 'editor', 'viewer']);
        (ac.grant(['editor', 'agent']).extendSync(['role2', 'role3'])).execute('update').on('photo');
        expect(Object.keys(ac.getGrants().editor.$extend).sort()).toEqual(['role2', 'role3']);

        ac.removeRoles(['editor', 'agent']);
        expect(ac.getGrants().editor).toBeUndefined();
        expect(ac.getGrants().agent).toBeUndefined();
        expect(ac.getGrants().admin.$extend['editor']).toBeUndefined();
        expect(ac.getGrants().admin.$extend['agent']).toBeUndefined();
        throwsError(() => ac.grant('roleX').extendSync('roleX'));
        throwsError(() => ac.grant(['admin2', 'roleX']).extendSync(['roleX', 'admin3']));
    });

    it('should throw error while trying extend own role', function () {
        let ac = this.ac;
        ac.grant('user').execute('create').when(categorySportsCondition).on('book');
        ac.extendRole('editor', 'user');
        ac.grant('editor').execute('delete').on('book');
        throwsAccessControlError(() => ac.extendRole('user', 'editor'));
        throwsAccessControlError(() => ac.extendRole('user', 'user'));
    });

    it('should throw error while trying extend own role synchronously', function () {
        let ac = this.ac;
        ac.grant('user').execute('create').when(categorySportsCondition).on('book');
        ac.extendRole('editor', 'user');
        ac.grant('editor').execute('delete').on('book');
        throwsError(() => ac.extendRole('user', 'editor'));
        throwsError(() => ac.extendRole('user', 'user'));
    });


    it('should extend roles when conditions used', async function () {
        let ac = this.ac;
        let sportsEditorGrant = {
            role: 'sports/editor',
            resource: 'post',
            action: 'create', // action
            attributes: ['*'], // grant only
            condition: categorySportsCondition
        };
        let politicsEditorGrant = {
            role: 'politics/editor',
            resource: 'post',
            action: 'create', // action
            attributes: ['*'], // grant only
            condition: categoryPoliticsCondition
        };
        ac.grant(sportsEditorGrant);
        ac.grant(politicsEditorGrant);
        ac.extendRole('editor', ['sports/editor', 'politics/editor']);
        expect((await ac.can('editor').context(categorySportsContext).execute('create').on('post')).granted).toEqual(true);
        expect((await ac.can('editor').context(categoryPoliticsContext).execute('create').on('post')).granted).toEqual(true);
    });

    it('should extend roles when conditions used synchronously', function () {
        let ac = this.ac;
        let sportsEditorGrant = {
            role: 'sports/editor',
            resource: 'post',
            action: 'create', // action
            attributes: ['*'], // grant only
            condition: categorySportsCondition
        };
        let politicsEditorGrant = {
            role: 'politics/editor',
            resource: 'post',
            action: 'create', // action
            attributes: ['*'], // grant only
            condition: categoryPoliticsCondition
        };
        ac.grant(sportsEditorGrant);
        ac.grant(politicsEditorGrant);
        ac.extendRole('editor', ['sports/editor', 'politics/editor']);
        expect((ac.can('editor').context(categorySportsContext).execute('create').sync().on('post')).granted).toEqual(true);
        expect((ac.can('editor').context(categoryPoliticsContext).execute('create').sync().on('post')).granted).toEqual(true);
    });

    it('should extend roles with conditions', async function () {
        let ac = this.ac;
        let editorGrant = {
            role: 'editor',
            resource: 'post',
            action: 'create', // action
            attributes: ['*'] // grant only
        };
        ac.grant(editorGrant);
        ac.extendRole('sports/editor', 'editor', categorySportsCondition);
        ac.extendRole('politics/editor', 'editor', categoryPoliticsCondition);

        expect((await ac.can('editor').execute('create').on('post')).granted).toEqual(true);
        expect((await ac.can('editor').context(categorySportsContext).execute('create').on('post')).granted).toEqual(true);
        expect((await ac.can('editor').context(categoryPoliticsContext).execute('create').on('post')).granted).toEqual(true);

        expect((await ac.can('sports/editor').context(categoryPoliticsContext).execute('create').on('post')).granted).toEqual(false);
        expect((await ac.can('sports/editor').context(categorySportsContext).execute('create').on('post')).granted).toEqual(true);

    });

    it('should extend roles with conditions synchronously', function () {
        let ac = this.ac;
        let editorGrant = {
            role: 'editor',
            resource: 'post',
            action: 'create', // action
            attributes: ['*'] // grant only
        };
        ac.grant(editorGrant);
        ac.extendRole('sports/editor', 'editor', categorySportsCondition);
        ac.extendRole('politics/editor', 'editor', categoryPoliticsCondition);

        expect((ac.can('editor').execute('create').sync().on('post')).granted).toEqual(true);
        expect((ac.can('editor').context(categorySportsContext).execute('create').sync().on('post')).granted).toEqual(true);
        expect((ac.can('editor').context(categoryPoliticsContext).execute('create').sync().on('post')).granted).toEqual(true);

        expect((ac.can('sports/editor').context(categoryPoliticsContext).execute('create').sync().on('post')).granted).toEqual(false);
        expect((ac.can('sports/editor').context(categorySportsContext).execute('create').sync().on('post')).granted).toEqual(true);

    });


    it('should support multi-level extension of roles when conditions used', async function () {
        let ac = this.ac;
        let editorGrant = {
            role: 'editor',
            resource: 'post',
            action: 'create', // action
            attributes: ['*'] // grant only
        };
        ac.grant(editorGrant);
        // first level of extension
        ac.extendRole('sports/editor', 'editor', categorySportsCondition);
        ac.extendRole('politics/editor', 'editor', categoryPoliticsCondition);

        // second level of extension
        ac.extendRole('sports-and-politics/editor', ['sports/editor', 'politics/editor']);
        expect((await ac.can('sports-and-politics/editor').context(categorySportsContext).execute('create').on('post')).granted).toEqual(true);
        expect((await ac.can('sports-and-politics/editor').context(categoryPoliticsContext).execute('create').on('post')).granted).toEqual(true);

        // third level of extension
        ac.extendRole('conditonal/sports-and-politics/editor', 'sports-and-politics/editor', {
            Fn: 'EQUALS',
            args: { status: 'draft' }
        });

        expect((await ac.can('conditonal/sports-and-politics/editor').context({
            category: 'sports',
            status: 'draft'
        }).execute('create').on('post')).granted).toEqual(true);

        expect((await ac.can('conditonal/sports-and-politics/editor').context({
            category: 'tech',
            status: 'draft'
        }).execute('create').on('post')).granted).toEqual(false);

        expect((await ac.can('conditonal/sports-and-politics/editor').context({
            category: 'sports',
            status: 'published'
        }).execute('create').on('post')).granted).toEqual(false);
    });

    it('should support multi-level extension of roles when conditions used synchronously', function () {
        let ac = this.ac;
        let editorGrant = {
            role: 'editor',
            resource: 'post',
            action: 'create', // action
            attributes: ['*'] // grant only
        };
        ac.grant(editorGrant);
        // first level of extension
        ac.extendRole('sports/editor', 'editor', categorySportsCondition);
        ac.extendRole('politics/editor', 'editor', categoryPoliticsCondition);

        // second level of extension
        ac.extendRole('sports-and-politics/editor', ['sports/editor', 'politics/editor']);
        expect((ac.can('sports-and-politics/editor').context(categorySportsContext).execute('create').sync().on('post')).granted).toEqual(true);
        expect((ac.can('sports-and-politics/editor').context(categoryPoliticsContext).execute('create').sync().on('post')).granted).toEqual(true);

        // third level of extension
        ac.extendRole('conditonal/sports-and-politics/editor', 'sports-and-politics/editor', {
            Fn: 'EQUALS',
            args: { status: 'draft' }
        });

        expect((ac.can('conditonal/sports-and-politics/editor').context({
            category: 'sports',
            status: 'draft'
        }).execute('create').sync().on('post')).granted).toEqual(true);

        expect((ac.can('conditonal/sports-and-politics/editor').context({
            category: 'tech',
            status: 'draft'
        }).execute('create').sync().on('post')).granted).toEqual(false);

        expect((ac.can('conditonal/sports-and-politics/editor').context({
            category: 'sports',
            status: 'published'
        }).execute('create').sync().on('post')).granted).toEqual(false);
    });

    it('should remove roles when conditions used', async function () {
        let ac = this.ac;
        let editorGrant = {
            role: 'editor',
            resource: 'post',
            action: 'create', // action
            attributes: ['*'] // grant only
        };
        ac.grant(editorGrant);
        ac.extendRole('sports/editor', 'editor', categorySportsCondition);
        ac.extendRole('politics/editor', 'editor', categoryPoliticsCondition);

        ac.removeRoles('editor');
        expect((await ac.can('sports/editor').context(categoryPoliticsContext).execute('create').on('post')).granted).toEqual(false);
        expect((await ac.can('sports/editor').context(categorySportsContext).execute('create').on('post')).granted).toEqual(false);
    });

    it('should remove roles when conditions used synchronously', function () {
        let ac = this.ac;
        let editorGrant = {
            role: 'editor',
            resource: 'post',
            action: 'create', // action
            attributes: ['*'] // grant only
        };
        ac.grant(editorGrant);
        ac.extendRole('sports/editor', 'editor', categorySportsCondition);
        ac.extendRole('politics/editor', 'editor', categoryPoliticsCondition);

        ac.removeRoles('editor');
        expect((ac.can('sports/editor').context(categoryPoliticsContext).execute('create').sync().on('post')).granted).toEqual(false);
        expect((ac.can('sports/editor').context(categorySportsContext).execute('create').sync().on('post')).granted).toEqual(false);
    });

    it('should throw if grant objects are invalid', async function () {
        let o,
            ac = this.ac;

        o = {
            role: '', // invalid role, should be non-empty string or array
            resource: 'post',
            action: 'create',
            attributes: ['*'] // grant only
        };
        expect(() => ac.grant(o)).toThrow();

        o = {
            role: 'moderator',
            resource: null, // invalid resource, should be non-empty string
            action: 'create',
            attributes: ['*'] // grant only
        };
        expect(() => ac.grant(o)).toThrow();

        o = {
            role: 'admin',
            resource: 'post',
            action: null, // invalid action, should be create|read|update|delete
            attributes: ['*'] // grant only
        };
        expect(() => ac.grant(o)).toThrow();

        o = {
            role: 'admin2',
            resource: 'post',
            action: 'create',
            attributes: ['*'] // grant only
        };
        expect(() => ac.grant(o)).not.toThrow();
        expect((await ac.can('admin2').execute('create').on('post')).granted).toEqual(true);
    });

    it('should throw if grant objects are invalid synchronously', function () {
        let o,
            ac = this.ac;

        o = {
            role: '', // invalid role, should be non-empty string or array
            resource: 'post',
            action: 'create',
            attributes: ['*'] // grant only
        };
        expect(() => ac.grant(o)).toThrow();

        o = {
            role: 'moderator',
            resource: null, // invalid resource, should be non-empty string
            action: 'create',
            attributes: ['*'] // grant only
        };
        expect(() => ac.grant(o)).toThrow();

        o = {
            role: 'admin',
            resource: 'post',
            action: null, // invalid action, should be create|read|update|delete
            attributes: ['*'] // grant only
        };
        expect(() => ac.grant(o)).toThrow();

        o = {
            role: 'admin2',
            resource: 'post',
            action: 'create',
            attributes: ['*'] // grant only
        };
        expect(() => ac.grant(o)).not.toThrow();
        expect((ac.can('admin2').execute('create').sync().on('post')).granted).toEqual(true);
    });

    it('should throw `AccessControlError` for invalid role', async function () {
        let ac = this.ac;
        throwsAccessControlError(() => ac.grant().execute('create').on());
        ac.setGrants(grantsObject);
        await promiseThrowsError(ac.can('invalid-role').execute('create').on('video'), 'Role not found');
    });

    it('should throw `AccessControlError` for invalid role synchronously', function () {
        let ac = this.ac;
        throwsAccessControlError(() => ac.grant().execute('create').on());
        ac.setGrants(grantsObject);
        throwsError(() => ac.can('invalid-role').execute('create').sync().on('video'), 'Role not found');
    });

    it('should filter granted attributes', async function () {
        let ac = this.ac,
            attrs = ['*', '!account.balance.credit', '!account.id', '!secret'],
            data = {
                name: 'Company, LTD.',
                address: {
                    city: 'istanbul',
                    country: 'TR'
                },
                account: {
                    id: 33,
                    taxNo: 12345,
                    balance: {
                        credit: 100,
                        deposit: 0
                    }
                },
                secret: {
                    value: 'hidden'
                }
            };
        ac.grant('user').execute('create').on('company', attrs);
        let permission = await (ac.can('user').execute('create').on('company'));
        expect(permission.granted).toEqual(true);
        let filtered = permission.filter(data);
        expect(filtered.name).toEqual(jasmine.any(String));
        expect(filtered.address).toEqual(jasmine.any(Object));
        expect(filtered.address.city).toEqual('istanbul');
        expect(filtered.account).toBeDefined();
        expect(filtered.account.id).toBeUndefined();
        expect(filtered.account.balance).toBeDefined();
        expect(filtered.account.credit).toBeUndefined();
        expect(filtered.secret).toBeUndefined();
    });

    it('should filter granted attributes synchronously', function () {
        let ac = this.ac,
            attrs = ['*', '!account.balance.credit', '!account.id', '!secret'],
            data = {
                name: 'Company, LTD.',
                address: {
                    city: 'istanbul',
                    country: 'TR'
                },
                account: {
                    id: 33,
                    taxNo: 12345,
                    balance: {
                        credit: 100,
                        deposit: 0
                    }
                },
                secret: {
                    value: 'hidden'
                }
            };
        ac.grant('user').execute('create').on('company', attrs);
        let permission = (ac.can('user').execute('create').sync().on('company'));
        expect(permission.granted).toEqual(true);
        let filtered = permission.filter(data);
        expect(filtered.name).toEqual(jasmine.any(String));
        expect(filtered.address).toEqual(jasmine.any(Object));
        expect(filtered.address.city).toEqual('istanbul');
        expect(filtered.account).toBeDefined();
        expect(filtered.account.id).toBeUndefined();
        expect(filtered.account.balance).toBeDefined();
        expect(filtered.account.credit).toBeUndefined();
        expect(filtered.secret).toBeUndefined();
    });

    it('Check with multiple roles changes grant list (issue #2)', async function () {
        let ac = this.ac;
        ac.grant('admin').execute('update').on('video')
            .grant(['user', 'admin']).execute('update').on('video');

        // Admin can update any video
        expect((await ac.can(['admin']).execute('update').on('video')).granted).toEqual(true);

        // Admin can update any or own video
        expect((await ac.can(['admin']).execute('update').on('video')).granted).toEqual(true);
        expect((await ac.can(['admin']).execute('update').on('video')).granted).toEqual(true);
    });

    it('Check with multiple roles changes grant list (issue #2) synchronously', function () {
        let ac = this.ac;
        ac.grant('admin').execute('update').on('video')
            .grant(['user', 'admin']).execute('update').on('video');

        // Admin can update any video
        expect((ac.can(['admin']).execute('update').sync().on('video')).granted).toEqual(true);

        // Admin can update any or own video
        expect((ac.can(['admin']).execute('update').sync().on('video')).granted).toEqual(true);
        expect((ac.can(['admin']).execute('update').sync().on('video')).granted).toEqual(true);
    });

    it('should grant multiple roles and multiple resources', async function () {
        let ac = this.ac;

        ac.grant('admin, user').execute('create').on('profile, video');
        expect((await ac.can('admin').execute('create').on('profile')).granted).toEqual(true);
        expect((await ac.can('admin').execute('create').on('video')).granted).toEqual(true);
        expect((await ac.can('user').execute('create').on('profile')).granted).toEqual(true);
        expect((await ac.can('user').execute('create').on('video')).granted).toEqual(true);

        ac.grant('admin, user').execute('create').on('profile, video', '*,!id');
        expect((await ac.can('admin').execute('create').on('profile')).attributes).toEqual(['*']);
        expect((await ac.can('admin').execute('create').on('video')).attributes).toEqual(['*']);
        expect((await ac.can('user').execute('create').on('profile')).attributes).toEqual(['*']);
        expect((await ac.can('user').execute('create').on('video')).attributes).toEqual(['*']);

        expect((await ac.can('user').execute('create').on('non-existent')).granted).toEqual(false);
    });

    it('should grant multiple roles and multiple resources synchronously', function () {
        let ac = this.ac;

        ac.grant('admin, user').execute('create').on('profile, video');
        expect((ac.can('admin').execute('create').sync().on('profile')).granted).toEqual(true);
        expect((ac.can('admin').execute('create').sync().on('video')).granted).toEqual(true);
        expect((ac.can('user').execute('create').sync().on('profile')).granted).toEqual(true);
        expect((ac.can('user').execute('create').sync().on('video')).granted).toEqual(true);

        ac.grant('admin, user').execute('create').on('profile, video', '*,!id');
        expect((ac.can('admin').execute('create').sync().on('profile')).attributes).toEqual(['*']);
        expect((ac.can('admin').execute('create').sync().on('video')).attributes).toEqual(['*']);
        expect((ac.can('user').execute('create').sync().on('profile')).attributes).toEqual(['*']);
        expect((ac.can('user').execute('create').sync().on('video')).attributes).toEqual(['*']);

        expect((ac.can('user').execute('create').sync().on('non-existent')).granted).toEqual(false);
    });
});

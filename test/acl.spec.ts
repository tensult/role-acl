const AccessControl = require('../src').AccessControl;

function type(o) {
    return Object.prototype.toString.call(o).match(/\s(\w+)/i)[1].toLowerCase();
}

function throwsAccessControlError(fn, errMsg?) {
    expect(fn).toThrow();
    try {
        fn();
    } catch (err) {
        expect(err instanceof AccessControl.Error).toEqual(true);
        expect(AccessControl.isACError(err)).toEqual(true);
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
    }

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

    it('should grant access and check permissions for wildcard resources', async function () {
        const ac = this.ac;
        const attrs = ['*', '!size'];
        const conditionalAttrs = [{
            attributes: attrs,
            condition: undefined
        }];

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

    it('should grant access with equals condition with list of values and check permissions', async function () {
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
        expect((await ac.can('user').context({ category: 'tech' }).execute('create').on('article')).granted).toEqual(false);
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

    it('should grant access with JSONPath context values with EQUALS condition', async function () {
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
    });

    it('should grant access with JSONPath context values with NOT_EQUALS condition', async function () {
        const ac = this.ac;
        ac.grant('user').condition(
            {
                Fn: 'NOT_EQUALS',
                args: {
                    'requester': '$.owner'
                }
            }).execute('approve').on('article');
        expect((await ac.can('user').context({ owner: 'dilip', requester: 'dilip' })
            .execute('approve').on('article')).granted).toEqual(false);
        expect((await ac.can('user').context({ owner: 'tensult', requester: 'dilip' })
            .execute('approve').on('article')).granted).toEqual(true);
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

    it('should grant access with not condition with list value and check permissions', async function () {
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

    it('should grant access with not condition with single value and check permissions', async function () {
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

    it('should grant access with list contains condition with single value and check permissions', async function () {
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

    it('should grant access with starts with condition with single value and check permissions', async function () {
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

    it('should grant access with starts with condition with list value and check permissions', async function () {
        const ac = this.ac;

        ac.grant('user').condition(
            {
                Fn: 'STARTS_WITH',
                args: {
                    tags: ['sports', 'politics']
                }
            }).execute('create').on('article');
        expect((await ac.can('user').context({ tags: 'sports' }).execute('create').on('article')).granted).toEqual(true);
        expect((await ac.can('user').context({ tags: 'politics' }).execute('create').on('article')).granted).toEqual(true);
        expect((await ac.can('user').context({ tags: 'tech' }).execute('create').on('article')).granted).toEqual(false);
    });

    it('should grant access with list contains condition with multiple value and check permissions', async function () {
        const ac = this.ac;

        ac.grant('user').condition(
            {
                Fn: 'LIST_CONTAINS',
                args: {
                    tags: ['sports', 'politics']
                }
            }).execute('create').on('article');
        expect((await ac.can('user').context({ tags: ['sports'] }).execute('create').on('article')).granted).toEqual(true);
        expect((await ac.can('user').context({ tags: ['politics'] }).execute('create').on('article')).granted).toEqual(true);
        expect((await ac.can('user').context({ tags: ['tech'] }).execute('create').on('article')).granted).toEqual(false);
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

    it('should return allowed resources for given roles', async function () {
        let ac = this.ac;
        ac.grant('user').condition(categorySportsCondition).execute('create').on('article');
        ac.grant('user').execute('*').on('image');
        await ac.extendRole('admin', 'user');
        ac.grant('admin').execute('*').on('category');
        await ac.extendRole('owner', 'admin');
        ac.grant('owner').execute('*').on('video');

        expect((await ac.allowedResources({ role: 'user' })).sort()).toEqual(['article', 'image']);
        expect((await ac.allowedResources({ role: 'user', context: categorySportsContext })).sort()).toEqual(['article', 'image']);
        expect((await ac.allowedResources({ role: 'user', context: categoryPoliticsContext })).sort()).toEqual(['image']);
        expect((await ac.allowedResources({ role: 'admin' })).sort()).toEqual(['article', 'category', 'image']);
        expect((await ac.allowedResources({ role: 'owner' })).sort()).toEqual(['article', 'category', 'image', 'video']);
        expect((await ac.allowedResources({ role: ['admin', 'owner'] })).sort()).toEqual(['article', 'category', 'image', 'video']);
    });

    it('should return allowed actions for given roles and resource', async function () {
        let ac = this.ac;
        ac.grant('user').condition(categorySportsCondition).execute('create').on('article');
        ac.grant('user').execute('*').on('image');
        await ac.extendRole('admin', 'user');
        ac.grant('admin').execute('delete').on('article');
        ac.grant('admin').execute('*').on('category');
        await ac.extendRole('owner', 'admin');
        ac.grant('owner').execute('*').on('video');

        expect((await ac.allowedActions({ role: 'user', resource: 'article' })).sort()).toEqual(['create']);
        expect((await ac.allowedActions({ role: 'user', resource: 'article', context: categorySportsContext })).sort()).toEqual(['create']);
        expect((await ac.allowedActions({ role: 'user', resource: 'article', context: categoryPoliticsContext }))).toEqual([]);
        expect((await ac.allowedActions({ role: ['admin', 'user'], resource: 'article' })).sort()).toEqual(['create', 'delete']);

        expect((await ac.allowedActions({ role: 'admin', resource: 'category' })).sort()).toEqual(['*']);
        expect((await ac.allowedActions({ role: 'owner', resource: 'video' })).sort()).toEqual(['*']);
    });

    it('should return allowing roles for given permission', async function () {
        let ac = this.ac;
        ac.setGrants(conditionalGrantObject);
        ac.grant('user').condition(categorySportsCondition).execute('create').on('blog');
        ac.grant('user').execute('*').on('image');
        await ac.extendRole('sports/editor', 'user');
        await ac.extendRole('admin', 'user');
        ac.grant('admin').execute('*').on('category');
        await ac.extendRole('owner', 'admin');
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
        // console.log(JSON.stringify(ac.getGrants(), null, "  "));
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

    it('should extend / remove roles', async function () {
        let ac = this.ac;

        ac.grant('admin').execute('create').on('book');
        await ac.extendRole('onur', 'admin');
        expect(ac.getGrants().onur.$extend['admin']).toEqual({ condition: undefined });

        ac.grant('role2, role3, editor, viewer, agent').execute('create').on('book');

        await ac.extendRole('onur', ['role2', 'role3']);
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
        try {
            await ac.grant('roleX').extend('roleX')
            fail('should throw error');
        } catch (error) {
        }
        try {
            await ac.grant(['admin2', 'roleX']).extend(['roleX', 'admin3'])
            fail('should throw error');
        } catch (error) {
        }
    });

    it('should throw error while trying extend own role', async function () {
        let ac = this.ac;
        ac.grant('user').execute('create').when(categorySportsCondition).on('book');
        await ac.extendRole('editor', 'user');
        ac.grant('editor').execute('delete').on('book');
        try {
            await ac.extendRole('user', 'editor')
            fail('should throw error');
        } catch (error) {
        }

        try {
            await ac.extendRole('user', 'user');
            fail('should throw error');
        } catch (error) {
        }
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
        await ac.extendRole('editor', ['sports/editor', 'politics/editor']);
        expect((await ac.can('editor').context(categorySportsContext).execute('create').on('post')).granted).toEqual(true);
        expect((await ac.can('editor').context(categoryPoliticsContext).execute('create').on('post')).granted).toEqual(true);
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
        await ac.extendRole('sports/editor', 'editor', categorySportsCondition);
        await ac.extendRole('politics/editor', 'editor', categoryPoliticsCondition);

        expect((await ac.can('editor').execute('create').on('post')).granted).toEqual(true);
        expect((await ac.can('editor').context(categorySportsContext).execute('create').on('post')).granted).toEqual(true);
        expect((await ac.can('editor').context(categoryPoliticsContext).execute('create').on('post')).granted).toEqual(true);

        expect((await ac.can('sports/editor').context(categoryPoliticsContext).execute('create').on('post')).granted).toEqual(false);
        expect((await ac.can('sports/editor').context(categorySportsContext).execute('create').on('post')).granted).toEqual(true);

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
        await ac.extendRole('sports/editor', 'editor', categorySportsCondition);
        await ac.extendRole('politics/editor', 'editor', categoryPoliticsCondition);

        // second level of extension
        await ac.extendRole('sports-and-politics/editor', ['sports/editor', 'politics/editor']);
        expect((await ac.can('sports-and-politics/editor').context(categorySportsContext).execute('create').on('post')).granted).toEqual(true);
        expect((await ac.can('sports-and-politics/editor').context(categoryPoliticsContext).execute('create').on('post')).granted).toEqual(true);

        // third level of extension
        await ac.extendRole('conditonal/sports-and-politics/editor', 'sports-and-politics/editor', {
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

    it('should remove roles when conditions used', async function () {
        let ac = this.ac;
        let editorGrant = {
            role: 'editor',
            resource: 'post',
            action: 'create', // action
            attributes: ['*'] // grant only
        };
        ac.grant(editorGrant);
        await ac.extendRole('sports/editor', 'editor', categorySportsCondition);
        await ac.extendRole('politics/editor', 'editor', categoryPoliticsCondition);

        ac.removeRoles('editor');
        expect((await ac.can('sports/editor').context(categoryPoliticsContext).execute('create').on('post')).granted).toEqual(false);
        expect((await ac.can('sports/editor').context(categorySportsContext).execute('create').on('post')).granted).toEqual(false);
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

    it('should throw `AccessControlError` for invalid role', async function () {
        let ac = this.ac;
        throwsAccessControlError(() => ac.grant().execute('create').on());
        ac.setGrants(grantsObject);
        try {
            await ac.can('invalid-role').execute('create').on('video');
            fail('should throw error');
        } catch (err) {
            expect(err instanceof AccessControl.Error).toEqual(true);
            expect(AccessControl.isACError(err)).toEqual(true);
            expect(err.message).toContain('Role not found');
        }
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

        // console.log(JSON.stringify(ac.getGrants(), null, "  "));
    });
});

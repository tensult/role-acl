/**
 *  Test Suite: AccessControl (Core)
 *  @author   Onur Yıldırım <onur@cutepilot.com>
 */

const AccessControl = require('../lib').AccessControl;

function type(o) {
    return Object.prototype.toString.call(o).match(/\s(\w+)/i)[1].toLowerCase();
}

function throwsAccessControlError(fn, errMsg) {
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
    'use strict';

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

    let categorySportsCondition = { "Fn": "EQUALS", "args": { "category": "sports" } };
    let categoryPoliticsCondition = { "Fn": "EQUALS", "args": { "category": "politics" } };
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
        "sports/editor":
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
        "sports/writer": {
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

    //----------------------------
    //  TESTS
    //----------------------------

    it('should add grants from flat list (db), check/remove roles and resources', function () {
        let ac = this.ac;
        ac.setGrants(grantList);
        // console.log('grants', ac.getGrants());
        // console.log('resources', ac.getResources());
        // console.log('roles', ac.getRoles());

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

    it('should add conditional grants from flat list (db), check/remove roles and resources', function () {
        let ac = this.ac;
        ac.setGrants(conditionalGrantList);
        // console.log('grants', ac.getGrants());
        // console.log('resources', ac.getResources());
        // console.log('roles', ac.getRoles());

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

    it('should grant access and check permissions', function () {
        const ac = this.ac;
        const attrs = ['*', '!size'];
        const conditionalAttrs = [{
            attributes: attrs,
            condition: undefined
        }];

        ac.grant('user').execute('create').on('photo', attrs);
        expect(ac.can('user').execute('create').on('photo').attributes).toEqual(attrs);

        // grant multiple roles the same permission for the same resource
        ac.grant(['user', 'admin']).execute('read').on('photo', attrs);
        expect(ac.can('user').execute('read').on('photo').granted).toEqual(true);
        expect(ac.can('admin').execute('read').on('photo').granted).toEqual(true);

        ac.grant('user').execute('update').on('photo', attrs);
        expect(ac.can('user').execute('update').on('photo').attributes).toEqual(attrs);


        ac.grant('user').execute('delete').on('photo', attrs);
        expect(ac.can('user').execute('delete').on('photo').attributes).toEqual(attrs);
    });

    it('should grant access and check permissions for wilded card resources', function () {
        const ac = this.ac;
        const attrs = ['*', '!size'];
        const conditionalAttrs = [{
            attributes: attrs,
            condition: undefined
        }];

        ac.grant('user1').execute('create').on('!photo', attrs);
        expect(ac.can('user1').execute('create').on('photo').granted).toEqual(false);
        expect(ac.can('user1').execute('create').on('video').granted).toEqual(true);
        ac.grant('user2').execute('create').on(['photo', 'video'], attrs);
        expect(ac.can('user2').execute('create').on('photo').granted).toEqual(true);
        expect(ac.can('user2').execute('create').on('video').granted).toEqual(true);
        ac.grant('user3').execute('create').on(['!(photo|video)'], attrs);
        expect(ac.can('user3').execute('create').on('photo').granted).toEqual(false);
        expect(ac.can('user3').execute('create').on('video').granted).toEqual(false);
    });

    it('should grant access and check permissions for wilded card actions', function () {
        const ac = this.ac;
        const attrs = ['*', '!size'];
        const conditionalAttrs = [{
            attributes: attrs,
            condition: undefined
        }];

        ac.grant('user1').execute('!create').on('photo', attrs);
        expect(ac.can('user1').execute('create').on('photo').granted).toEqual(false);
        expect(ac.can('user1').execute('update').on('photo').granted).toEqual(true);

        ac.grant('user1').execute(['*', '!create']).on('photo', attrs);
        expect(ac.can('user1').execute('create').on('photo').granted).toEqual(false);
        expect(ac.can('user1').execute('update').on('photo').granted).toEqual(true);
        expect(ac.can('user1').execute('update').on('photo').granted).toEqual(true);

        ac.grant('user2').execute(['create', 'update']).on(['photo'], attrs);
        expect(ac.can('user2').execute('update').on('photo').granted).toEqual(true);
        expect(ac.can('user2').execute('create').on('photo').granted).toEqual(true);

        ac.grant('user3').execute(['*', '!(create|update)']).on(['photo'], attrs);
        expect(ac.can('user3').execute('update').on('photo').granted).toEqual(false);
        expect(ac.can('user3').execute('create').on('photo').granted).toEqual(false);
    });

    it('should filter object properties', function () {
        expect(AccessControl.filter({ status: 'approved', id: 123 }, ['*', '!status'])).toEqual({ id: 123 });
        expect(AccessControl.filter({ status: 'approved', id: 123 }, ['*'])).toEqual({ status: 'approved', id: 123 });
    })

    it('should grant access with custom actions and check permissions', function () {
        const ac = this.ac;
        const attrs = ['*', '!status'];
        const conditionalAttrs = [{
            attributes: attrs,
            condition: undefined
        }];

        ac.grant('editor').execute('publish').on('article', attrs);
        let permission = ac.can('editor').execute('publish').on('article');
        expect(permission.attributes).toEqual(attrs);
        expect(permission.granted).toEqual(true);

        ac.grant('sports/editor').execute('publish').when(categorySportsCondition).on('article', attrs);
        permission = ac.can('sports/editor').execute('publish').with(categorySportsContext).on('article');
        expect(permission.attributes).toEqual(attrs);
        expect(permission.granted).toEqual(true);

        permission = ac.can('sports/editor').execute('publish').with(categoryPoliticsContext).on('article');
        expect(permission.attributes).toEqual([]);
        expect(permission.granted).toEqual(false);

        ac.grant({
            role: 'politics/editor',
            action: 'publish',
            resource: 'article',
            condition: categoryPoliticsCondition,
            attributes: attrs
        });
        permission = ac.can('politics/editor').execute('publish').with(categoryPoliticsContext).on('article');
        expect(permission.attributes).toEqual(attrs);
        expect(permission.granted).toEqual(true);

        // Simply set all the fields and call commit at the end
        ac.grant('user')
            .action('post')
            .resource('blog')
            .attributes(attrs)
            .condition({ Fn: 'EQUALS', args: { logged: true } })
            .commit();
        permission = ac.can('user').execute('post').with({ logged: true }).on('blog');
        expect(permission.attributes).toEqual(attrs);
        expect(permission.granted).toEqual(true);
    });

    it('should grant access with OR condition and check permissions', function () {
        const ac = this.ac;

        ac.grant('user').condition(
            {
                Fn: 'OR',
                args: [
                    categorySportsCondition,
                    categoryPoliticsCondition
                ]
            }).execute('create').on('article');
        expect(ac.can('user').context(categorySportsContext).execute('create').on('article').granted).toEqual(true);
        expect(ac.can('user').context(categoryPoliticsContext).execute('create').on('article').granted).toEqual(true);
        expect(ac.can('user').context({ category: 'tech' }).execute('create').on('article').granted).toEqual(false);

    });

    it('should grant access with equals condition with list of values and check permissions', function () {
        const ac = this.ac;

        ac.grant('user').condition(
            {
                Fn: 'EQUALS',
                args: {
                    'category': ['sports', 'politics']
                }
            }).execute('create').on('article');
        expect(ac.can('user').context(categorySportsContext).execute('create').on('article').granted).toEqual(true);
        expect(ac.can('user').context(categoryPoliticsContext).execute('create').on('article').granted).toEqual(true);
        expect(ac.can('user').context({ category: 'tech' }).execute('create').on('article').granted).toEqual(false);
    });

    it('should grant access with equals condition with single and check permissions', function () {
        const ac = this.ac;

        ac.grant('user').condition(
            {
                Fn: 'EQUALS',
                args: {
                    'category': 'sports'
                }
            }).execute('create').on('article');
        expect(ac.can('user').context(categorySportsContext).execute('create').on('article').granted).toEqual(true);
        expect(ac.can('user').context({ category: 'tech' }).execute('create').on('article').granted).toEqual(false);
    });

    it('should grant access with not equals condition with list of values and check permissions', function () {
        const ac = this.ac;

        ac.grant('user').condition(
            {
                Fn: 'NOT_EQUALS',
                args: {
                    'category': ['sports', 'politics']
                }
            }).execute('create').on('article');
        expect(ac.can('user').context(categorySportsContext).execute('create').on('article').granted).toEqual(false);
        expect(ac.can('user').context(categoryPoliticsContext).execute('create').on('article').granted).toEqual(false);
        expect(ac.can('user').context({ category: 'tech' }).execute('create').on('article').granted).toEqual(true);
    });

    it('should grant access with not equals condition with single value and check permissions', function () {
        const ac = this.ac;

        ac.grant('user').condition(
            {
                Fn: 'NOT_EQUALS',
                args: {
                    'category': 'sports'
                }
            }).execute('create').on('article');
        expect(ac.can('user').context(categorySportsContext).execute('create').on('article').granted).toEqual(false);
        expect(ac.can('user').context({ category: 'tech' }).execute('create').on('article').granted).toEqual(true);
    });

    it('should grant access with and condition with list value and check permissions', function () {
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
        expect(ac.can('user').context(categorySportsContext).execute('create').on('article').granted).toEqual(false);
        expect(ac.can('user').context(categoryPoliticsContext).execute('create').on('article').granted).toEqual(false);
        expect(ac.can('user').context({ category: 'tech' }).execute('create').on('article').granted).toEqual(true);
    });

    it('should grant access with and condition with single value and check permissions', function () {
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
        expect(ac.can('user').context(categorySportsContext).execute('create').on('article').granted).toEqual(false);
        expect(ac.can('user').context({ category: 'tech' }).execute('create').on('article').granted).toEqual(true);
    });

    it('should grant access with not condition with list value and check permissions', function () {
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
        expect(ac.can('user').context(categorySportsContext).execute('create').on('article').granted).toEqual(false);
        expect(ac.can('user').context(categoryPoliticsContext).execute('create').on('article').granted).toEqual(false);
        expect(ac.can('user').context({ category: 'tech' }).execute('create').on('article').granted).toEqual(true);
    });

    it('should grant access with not condition with single value and check permissions', function () {
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
        expect(ac.can('user').context(categorySportsContext).execute('create').on('article').granted).toEqual(false);
        expect(ac.can('user').context({ category: 'tech' }).execute('create').on('article').granted).toEqual(true);
    });

    it('should grant access with list contains condition with single value and check permissions', function () {
        const ac = this.ac;

        ac.grant('user').condition(
            {
                Fn: 'LIST_CONTAINS',
                args: {
                    tags: 'sports'
                }
            }).execute('create').on('article');
        expect(ac.can('user').context({ tags: ['sports'] }).execute('create').on('article').granted).toEqual(true);
        expect(ac.can('user').context({ tags: ['politics'] }).execute('create').on('article').granted).toEqual(false);
    });

    it('should grant access with starts with condition with single value and check permissions', function () {
        const ac = this.ac;

        ac.grant('user').condition(
            {
                Fn: 'STARTS_WITH',
                args: {
                    tags: 'sports'
                }
            }).execute('create').on('article');
        expect(ac.can('user').context({ tags: 'sports' }).execute('create').on('article').granted).toEqual(true);
        expect(ac.can('user').context({ tags: 'politics' }).execute('create').on('article').granted).toEqual(false);
    });

    it('should grant access with starts with condition with list value and check permissions', function () {
        const ac = this.ac;

        ac.grant('user').condition(
            {
                Fn: 'STARTS_WITH',
                args: {
                    tags: ['sports', 'politics']
                }
            }).execute('create').on('article');
        expect(ac.can('user').context({ tags: 'sports' }).execute('create').on('article').granted).toEqual(true);
        expect(ac.can('user').context({ tags: 'politics' }).execute('create').on('article').granted).toEqual(true);
        expect(ac.can('user').context({ tags: 'tech' }).execute('create').on('article').granted).toEqual(false);
    });

    it('should grant access with list contains condition with multiple value and check permissions', function () {
        const ac = this.ac;

        ac.grant('user').condition(
            {
                Fn: 'LIST_CONTAINS',
                args: {
                    tags: ['sports', 'politics']
                }
            }).execute('create').on('article');
        expect(ac.can('user').context({ tags: ['sports'] }).execute('create').on('article').granted).toEqual(true);
        expect(ac.can('user').context({ tags: ['politics'] }).execute('create').on('article').granted).toEqual(true);
        expect(ac.can('user').context({ tags: ['tech'] }).execute('create').on('article').granted).toEqual(false);
    });

    it('should grant access to attribute based on conditions', function () {
        const ac = this.ac;
        const sportsAttrs = ['sportsField'];
        const politicsAttrs = ['politicsField'];

        ac.grant('user').condition(categorySportsCondition).execute('create').on('article', sportsAttrs);
        ac.grant('user').condition(categoryPoliticsCondition).attributes(politicsAttrs).execute('create').on('article');
        expect(ac.can('user').context(categorySportsContext).execute('create').on('article').granted).toEqual(true);
        expect(ac.can('user').context(categorySportsContext).execute('create').on('article').attributes).toEqual(sportsAttrs);
        expect(ac.can('user').context(categoryPoliticsContext).execute('create').on('article').granted).toEqual(true);
        expect(ac.can('user').context(categoryPoliticsContext).execute('create').on('article').attributes).toEqual(politicsAttrs);

    });

    it('should add conditional grants with list and check permissions', function () {
        const ac = this.ac;
        ac.setGrants(conditionalGrantList);
        const editorAttrs = ['*'];
        const writerAttrs = ['*', '!status'];
        expect(ac.can('sports/editor').context(categorySportsContext).execute('create').on('article').attributes).toEqual(editorAttrs);
        expect(ac.can('sports/editor').context(categoryPoliticsContext).execute('update').on('article').granted).toEqual(false);
        expect(ac.can('sports/writer').context(categorySportsContext).execute('create').on('article').attributes).toEqual(writerAttrs);
        expect(ac.can('sports/writer').context(categoryPoliticsContext).execute('update').on('article').granted).toEqual(false);
        // should fail when context is not passed
        expect(ac.can('sports/writer').execute('create').on('article').granted).toEqual(false);
    });

    it('should chain grant methods and check permissions', function () {
        let ac = this.ac,
            attrs = ['*'];

        ac.grant('superadmin')
            .execute('create').on('profile', attrs)
            .execute('read').on('profile', attrs)
            .execute('create').on('video', []) // no attributes allowed
            .execute('create').on('photo'); // all attributes allowed

        expect(ac.can('superadmin').execute('create').on('profile').granted).toEqual(true);
        expect(ac.can('superadmin').execute('read').on('profile').granted).toEqual(true);
        expect(ac.can('superadmin').execute('create').on('video').granted).toEqual(false);
        expect(ac.can('superadmin').execute('create').on('photo').granted).toEqual(true);
    });

    it('should grant access via object and check permissions', function () {
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

        expect(ac.can('moderator').execute('create').on('post').granted).toEqual(true);
        expect(ac.can('moderator').execute('read').on('news').granted).toEqual(true);
        expect(ac.can('moderator').execute('update').on('book').granted).toEqual(true);


        // should overwrite already defined action in o1 object
        ac.grant(o1).execute('read').on();
        expect(ac.can('moderator').execute('read').on('post').granted).toEqual(true);

        // non-set action (update:own)
        expect(ac.can('moderator').execute('update').on('news').granted).toEqual(false);
        // non-existent resource
        expect(ac.can('moderator').execute('create').on('foo').granted).toEqual(false);
    });

    it('should grant conditional access via object and check permissions', function () {
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

        expect(ac.can('moderator').context(categorySportsContext).execute('create').on('post').granted).toEqual(true);
        expect(ac.can('moderator').context(categorySportsContext).execute('read').on('news').granted).toEqual(true);
        expect(ac.can('moderator').context(categorySportsContext).execute('update').on('book').granted).toEqual(true);


        // should overwrite already defined action in o1 object
        ac.grant(o1).execute('read').on();
        expect(ac.can('moderator').context(categorySportsContext).execute('read').on('post').granted).toEqual(true);

        // non-set action (update:own)
        expect(ac.can('moderator').context(categorySportsContext).execute('update').on('news').granted).toEqual(false);
        // non-existent resource
        expect(ac.can('moderator').context(categorySportsContext).execute('create').on('foo').granted).toEqual(false);
    });

    it('should skip conditions when skipConditions is used', function () {
        let ac = this.ac;
        ac.grant('user').condition(categorySportsCondition).execute('create').on('article');
        expect(ac.permission({
            role: 'user', action: 'create', resource: 'article', context: categorySportsContext
        }).granted).toEqual(true);
        expect(ac.can('user').execute('create').with(categorySportsContext).on('article').granted).toEqual(true);
        expect(ac.can('user').execute('create').on('article', true).granted).toEqual(true); // conditions skipped
        expect(ac.can('user').execute('create').on('article', false).granted).toEqual(false); // context not set
        expect(ac.can('user').execute('create').on('article').granted).toEqual(false); // context not set     
        expect(ac.permission({ role: 'user', action: 'create', resource: 'article' }).granted).toEqual(false); // context not set 
        // context not set and conditions skipped  
        expect(ac.permission({ role: 'user', action: 'create', resource: 'article', skipConditions: true }).granted).toEqual(true);

    });

    it('should grant access (variation, chained)', function () {
        let ac = this.ac;
        ac.setGrants(grantsObject);

        expect(ac.can('admin').execute('create').on('video').granted).toEqual(true);

        ac.grant('foo').execute('create').on('bar');
        expect(ac.can('foo').execute('create').on('bar').granted).toEqual(true);

        ac.grant('foo').execute('create').on('baz', []); // no attributes, actually denied instead of granted
        expect(ac.can('foo').execute('create').on('baz').granted).toEqual(false);

        ac.grant('qux')
            .execute('create').on('resource1')
            .execute('update').on('resource2')
            .execute('read').on('resource1')
            .execute('delete').on('resource1', []);
        expect(ac.can('qux').execute('create').on('resource1').granted).toEqual(true);
        expect(ac.can('qux').execute('update').on('resource2').granted).toEqual(true);
        expect(ac.can('qux').execute('read').on('resource1').granted).toEqual(true);
        expect(ac.can('qux').execute('delete').on('resource1').granted).toEqual(false);

        ac.grant('editor').resource('file1').execute('update').on();
        ac.grant().role('editor').execute('update').on('file2');
        ac.grant().role('editor').resource('file3').execute('update').on();
        expect(ac.can('editor').execute('update').on('file1').granted).toEqual(true);
        expect(ac.can('editor').execute('update').on('file2').granted).toEqual(true);
        expect(ac.can('editor').execute('update').on('file3').granted).toEqual(true);

        ac.grant('editor')
            .resource('fileX').execute('read').on().execute('create').on()
            .resource('fileY').execute('update').on().execute('delete').on();
        expect(ac.can('editor').execute('read').on('fileX').granted).toEqual(true);
        expect(ac.can('editor').execute('create').on('fileX').granted).toEqual(true);
        expect(ac.can('editor').execute('update').on('fileY').granted).toEqual(true);
        expect(ac.can('editor').execute('delete').on('fileY').granted).toEqual(true);

    });

    it('should switch-chain grant roles', function () {
        let ac = this.ac;
        ac.grant('r1')
            .execute('create').on('a')
            .grant('r2')
            .execute('create').on('b')
            .execute('read').on('b')
            .grant('r1')
            .execute('update').on('c')

        expect(ac.can('r1').execute('create').on('a').granted).toEqual(true);
        expect(ac.can('r1').execute('update').on('c').granted).toEqual(true);
        expect(ac.can('r2').execute('create').on('b').granted).toEqual(true);
        expect(ac.can('r2').execute('read').on('b').granted).toEqual(true);
        // console.log(JSON.stringify(ac.getGrants(), null, '  '));
    });

    it('should grant comma/semi-colon separated roles', function () {
        let ac = this.ac;
        // also supporting comma/semi-colon separated roles
        ac.grant('role2; role3, editor; viewer, agent').execute('create').on('book');
        expect(ac.hasRole('role3')).toEqual(true);
        expect(ac.hasRole('editor')).toEqual(true);
        expect(ac.hasRole('agent')).toEqual(true);
    });

    it('permission should also return queried role(s) and resource', function () {
        let ac = this.ac;
        // also supporting comma/semi-colon separated roles
        ac.grant('foo, bar').execute('create').on('baz');
        expect(ac.can('bar').execute('create').on('baz').granted).toEqual(true);
        // returned permission should provide queried role(s) as array
        expect(ac.can('foo').execute('create').on('baz').roles).toContain('foo');
        // returned permission should provide queried resource
        expect(ac.can('foo').execute('create').on('baz').resource).toEqual('baz');
        // create is execute('create').on. but above only returns the queried value, not the result.
    });

    it('should extend / remove roles', function () {
        let ac = this.ac;

        ac.grant('admin').execute('create').on('book');
        ac.extendRole('onur', 'admin');
        expect(ac.getGrants().onur.$extend.length).toEqual(1);
        expect(ac.getGrants().onur.$extend[0].role).toEqual('admin');

        ac.grant('role2, role3, editor, viewer, agent').execute('create').on('book');

        ac.extendRole('onur', ['role2', 'role3']);
        expect(ac.getGrants().onur.$extend.map((elm) => { return elm.role })).toEqual(['admin', 'role2', 'role3']);

        ac.grant('admin').extend('editor');
        expect(ac.getGrants().admin.$extend.map((elm) => { return elm.role })).toEqual(['editor']);
        ac.grant('admin').extend(['viewer', 'editor', 'agent']).execute('read').on('video');
        let extendedRoles = ac.getGrants().admin.$extend.map((elm) => { return elm.role });
        expect(extendedRoles).toContain('editor');
        expect(extendedRoles).toContain('agent');
        expect(extendedRoles).toContain('viewer');

        ac.grant(['editor', 'agent']).extend(['role2', 'role3']).execute('update').on('photo');
        expect(ac.getGrants().editor.$extend.map((elm) => { return elm.role })).toEqual(['role2', 'role3']);

        ac.removeRoles(['editor', 'agent']);
        expect(ac.getGrants().editor).toBeUndefined();
        expect(ac.getGrants().agent).toBeUndefined();
        expect(ac.getGrants().admin.$extend.map((elm) => { return elm.role })).not.toContain('editor');
        expect(ac.getGrants().admin.$extend.map((elm) => { return elm.role })).not.toContain('agent');

        expect(() => ac.grant('roleX').extend('roleX')).toThrow();
        expect(() => ac.grant(['admin2', 'roleX']).extend(['roleX', 'admin3'])).toThrow();

        // console.log(JSON.stringify(ac.getGrants(), null, '  '));
    });

    it('should extend roles when conditions used', function () {
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
        expect(ac.can('editor').context(categorySportsContext).execute('create').on('post').granted).toEqual(true);
        expect(ac.can('editor').context(categoryPoliticsContext).execute('create').on('post').granted).toEqual(true);
    });

    it('should extend roles with conditions', function () {
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

        expect(ac.can('editor').execute('create').on('post').granted).toEqual(true);
        expect(ac.can('editor').context(categorySportsContext).execute('create').on('post').granted).toEqual(true);
        expect(ac.can('editor').context(categoryPoliticsContext).execute('create').on('post').granted).toEqual(true);

        expect(ac.can('sports/editor').context(categoryPoliticsContext).execute('create').on('post').granted).toEqual(false);
        expect(ac.can('sports/editor').context(categorySportsContext).execute('create').on('post').granted).toEqual(true);

    });

    it('should support multi-level extension of roles when conditions used', function () {
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
        expect(ac.can('sports-and-politics/editor').context(categorySportsContext).execute('create').on('post').granted).toEqual(true);
        expect(ac.can('sports-and-politics/editor').context(categoryPoliticsContext).execute('create').on('post').granted).toEqual(true);

        // third level of extension
        ac.extendRole('conditonal/sports-and-politics/editor', 'sports-and-politics/editor', {
            Fn: 'EQUALS',
            args: { status: 'draft' }
        });

        expect(ac.can('conditonal/sports-and-politics/editor').context({
            category: 'sports',
            status: 'draft'
        }).execute('create').on('post').granted).toEqual(true);

        expect(ac.can('conditonal/sports-and-politics/editor').context({
            category: 'tech',
            status: 'draft'
        }).execute('create').on('post').granted).toEqual(false);

        expect(ac.can('conditonal/sports-and-politics/editor').context({
            category: 'sports',
            status: 'published'
        }).execute('create').on('post').granted).toEqual(false);
    });

    it('should remove roles when conditions used', function () {
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
        expect(ac.can('sports/editor').context(categoryPoliticsContext).execute('create').on('post').granted).toEqual(false);
        expect(ac.can('sports/editor').context(categorySportsContext).execute('create').on('post').granted).toEqual(false);
    });

    it('should throw if grant objects are invalid', function () {
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
        expect(ac.can('admin2').execute('create').on('post').granted).toEqual(true);
    });

    it('should throw `AccessControlError`', function () {
        let ac = this.ac;
        throwsAccessControlError(() => ac.grant().execute('create').on());
        ac.setGrants(grantsObject);
        throwsAccessControlError(() => ac.can('invalid-role').execute('create').on('video'), 'Role not found');
    });

    it('should filter granted attributes', function () {
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
        let permission = ac.can('user').execute('create').on('company');
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

    it('Check with multiple roles changes grant list (issue #2)', function () {
        let ac = this.ac;
        ac.grant('admin').execute('update').on('video')
            .grant(['user', 'admin']).execute('update').on('video');

        // Admin can update any video
        expect(ac.can(['admin']).execute('update').on('video').granted).toEqual(true);

        // Admin can update any or own video
        expect(ac.can(['admin']).execute('update').on('video').granted).toEqual(true);
        expect(ac.can(['admin']).execute('update').on('video').granted).toEqual(true);
    });

    it('should grant multiple roles and multiple resources', function () {
        let ac = this.ac;

        ac.grant('admin, user').execute('create').on('profile, video');
        expect(ac.can('admin').execute('create').on('profile').granted).toEqual(true);
        expect(ac.can('admin').execute('create').on('video').granted).toEqual(true);
        expect(ac.can('user').execute('create').on('profile').granted).toEqual(true);
        expect(ac.can('user').execute('create').on('video').granted).toEqual(true);

        ac.grant('admin, user').execute('create').on('profile, video', '*,!id');
        expect(ac.can('admin').execute('create').on('profile').attributes).toEqual(['*', '!id']);
        expect(ac.can('admin').execute('create').on('video').attributes).toEqual(['*', '!id']);
        expect(ac.can('user').execute('create').on('profile').attributes).toEqual(['*', '!id']);
        expect(ac.can('user').execute('create').on('video').attributes).toEqual(['*', '!id']);

        expect(ac.can('user').execute('create').on('non-existent').granted).toEqual(false);

        // console.log(JSON.stringify(ac.getGrants(), null, '  '));
    });
});

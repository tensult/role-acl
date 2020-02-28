[![Donate](https://img.shields.io/badge/Donate-PayPal-green.svg)](https://www.paypal.com/cgi-bin/webscr?cmd=_s-xclick&hosted_button_id=73QY55FZWSPRJ) [![Build Status](https://travis-ci.org/tensult/role-acl.png?branch=master)](https://travis-ci.org/tensult/role-acl) [![Test Coverage](https://api.codeclimate.com/v1/badges/2d748a99b2c54e057cc2/test_coverage)](https://codeclimate.com/github/tensult/role-acl/test_coverage) [![NPM Version](https://badge.fury.io/js/role-acl.svg?style=flat)](https://npmjs.org/package/role-acl) [![contributions welcome](https://img.shields.io/badge/contributions-welcome-brightgreen.svg?style=flat)](https://github.com/tensult/role-acl/issues)

Role, Attribute and conditions based Access Control for Node.js  

`npm i role-acl --save`  

Many [RBAC][rbac] (Role-Based Access Control) implementations differ, but the basics is widely adopted since it simulates real life role (job) assignments. But while data is getting more and more complex; you need to define policies on resources, subjects or even environments. This is called [ABAC][abac] (Attribute-Based Access Control).

With the idea of merging the best features of the two (see this [NIST paper][nist-paper]); this library implements RBAC basics and also focuses on *resource*, *action* attributes and conditions.

This library is an extension of [AccessControl][onury-accesscontrol]. But I removed support for possession and deny statements from orginal implementation.

### Core Features

- Chainable, friendly API.  
e.g. `ac.can(role).execute('create').on(resource)`
- Role hierarchical inheritance.
- Define grants at once (e.g. from database result) or one by one.
- Grant permissions by resources and actions define by glob notation.
- Grant permissions by attributes defined by glob notation (with nested object support).
- Ability to filter data (model) instance by allowed attributes.
- Ability to control access using conditions.
- Supports AND, OR, NOT, EQUALS, NOT_EQUALS, STARTS_WITH, LIST_CONTAINS conditions.
- You can specify dynamic context values in the conditions using JSON Paths.
- You can define your own condition functions too but please note if you use custom functions instead of standard conditions, you won't be able to save them as json in the DB.
- Policies are JSON compatible so can be stored and retrieved from database.
- Fast. (Grants are stored in memory, no database queries.)
- TypeScript support.
- **Note**: 
  - For versions < 4.0: follow this [ReadMe](https://github.com/tensult/role-acl/blob/6cde220e5d4956270c60f5fe58f84dcd8a257924/README.md).

## Guide

```js
const AccessControl = require('role-acl');
// or:
// import { AccessControl } from 'role-acl';
```

## Examples
### Basic Examples
Define roles and grants one by one.
```js
const ac = new AccessControl();
ac.grant('user')                    // define new or modify existing role. also takes an array.
    .execute('create').on('video')             // equivalent to .execute('create').on('video', ['*'])
    .execute('delete').on('video')
    .execute('read').on('video')
  .grant('admin')                   // switch to another role without breaking the chain
    .extend('user')                 // inherit role capabilities. also takes an array
    .execute('update').on('video', ['title'])  // explicitly defined attributes
    .execute('delete').on('video');

const permission = ac.can('user').execute('create').sync().on('video'); // <-- Sync Example
const permission = await ac.can('user').execute('create').on('video'); // <-- Async Example
console.log(permission.granted);    // —> true
console.log(permission.attributes); // —> ['*'] (all attributes)

permission = ac.can('admin').execute('update').sync().on('video'); // <-- Sync Example
permission = await ac.can('admin').execute('update').on('video'); // <-- Async Example
console.log(permission.granted);    // —> true
console.log(permission.attributes); // —> ['title']
```

### Conditions Examples

```js
const ac = new AccessControl();
ac.grant('user').condition(
    {
        Fn: 'EQUALS',
        args: {
            'category': 'sports'
        }
    }).execute('create').on('article');

let permission = ac.can('user').context({ category: 'sports' }).execute('create').sync().on('article'); // <-- Sync Example
let permission = await ac.can('user').context({ category: 'sports' }).execute('create').on('article'); // <-- Async Example
console.log(permission.granted);    // —> true
console.log(permission.attributes); // —> ['*'] (all attributes)

permission = ac.can('user').context({ category: 'tech' }).execute('create').sync().on('article'); // <-- Sync Example
permission = await ac.can('user').context({ category: 'tech' }).execute('create').on('article'); // <-- Async Example
console.log(permission.granted);    // —> false
console.log(permission.attributes); // —> []

// Condition with dynamic context values using JSONPath
// We can use this to allow only owner of the article to edit it
ac.grant('user').condition(
    {
        Fn: 'EQUALS',
        args: {
            'requester': '$.owner'
        }
    }).execute('edit').on('article');

permission =  ac.can('user').context({ requester: 'dilip', owner: 'dilip' }).execute('edit').sync().on('article'); // <-- Sync Example
permission =  await ac.can('user').context({ requester: 'dilip', owner: 'dilip' }).execute('edit').on('article'); // <-- Async Example
console.log(permission.granted);    // —> true

// We can use this to prevent someone to approve their own article so that it goes to review 
// by someone else before publishing
ac.grant('user').condition(
    {
        Fn: 'NOT_EQUALS',
        args: {
            'requester': '$.owner'
        }
    }).execute('approve').on('article');

permission = ac.can('user').context({ requester: 'dilip', owner: 'dilip' }).execute('approve').sync().on('article'); // <-- Sync Example
permission = await ac.can('user').context({ requester: 'dilip', owner: 'dilip' }).execute('approve').on('article'); // <-- Async Example
console.log(permission.granted);    // —> false

// Using custom/own condition functions
ac.grant('user').condition(
    (context) => {
        return context.category !== 'politics'
    }
).execute('create').on('article');
permission = ac.can('user').context({ category: 'sports' }).execute('create').sync().on('article'); // <-- Sync Example
permission = await ac.can('user').context({ category: 'sports' }).execute('create').on('article'); // <-- Async Example
console.log(permission.granted);    // —> true
```

### Wildcard (glob notation) Resource and Actions Examples
```js
ac.grant({
    role: 'politics/editor',
    action: '*',
    resource: 'article',
    condition: {Fn: 'EQUALS', args: {category: 'politics'}},
    attributes: ['*']
});
ac.grant({
    role: 'politics/writer',
    action: ['*', '!publish'],
    resource: 'article',
    condition: {Fn: 'EQUALS', args: {category: 'politics'}},
    attributes: ['*']
});

ac.grant({
    role: 'admin',
    action: '*',
    resource: '*',
    condition: {Fn: 'EQUALS', args: {category: 'politics'}},
    attributes: ['*']
});
permission = ac.can('politics/editor').execute('publish').with({category: 'politics'}).sync().on('article'); // <-- Sync Example
permission = await ac.can('politics/editor').execute('publish').with({category: 'politics'}).on('article'); // <-- Async Example
console(permission.attributes); // -> ['*']
console(permission.granted); // -> true

permission = ac.can('admin').execute('publish').with({category: 'politics'}).sync().on('article'); // <-- Sync Example
permission = await ac.can('admin').execute('publish').with({category: 'politics'}).on('article'); // <-- Async Example
console(permission.attributes); // -> ['*']
console(permission.granted); // -> true

permission = ac.can('admin').execute('publish').with({category: 'politics'}).sync().on('blog'); // <-- Sync Example
permission = await ac.can('admin').execute('publish').with({category: 'politics'}).on('blog'); // <-- Async Example
console(permission.attributes); // -> ['*']
console(permission.granted); // -> true

permission = ac.can('politics/writer').execute('publish').with({category: 'politics'}).sync().on('arti`cle'); // <-- Sync Example
permission = await ac.can('politics/writer').execute('publish').with({category: 'politics'}).on('arti`cle'); // <-- Async Example
console(permission.granted); // -> false
```

### Express.js Example

Check role permissions for the requested resource and action, if granted; respond with filtered attributes.

```js
const ac = new AccessControl(grants);
// ...
router.get('/videos/:title', function (req, res, next) {
    const permission = ac.can(req.user.role).execute('read').on('video');
    if (permission.granted) {
        Video.find(req.params.title, function (err, data) {
            if (err || !data) return res.status(404).end();
            // filter data by permission attributes and send.
            res.json(permission.filter(data));
        });
    } else {
        // resource is forbidden for this user/role
        res.status(403).end();
    }
});
```

### Roles

You can create/define roles simply by calling `.grant(<role>)` method on an `AccessControl` instance.  

Roles can extend other roles.

```js
// user role inherits viewer role permissions
ac.grant('user').extend('viewer');
// admin role inherits both user and editor role permissions
ac.grant('admin').extend(['user', 'editor']);
// both admin and superadmin roles inherit moderator permissions
ac.grant(['admin', 'superadmin']).extend('moderator');
```

### Actions and Action-Attributes

```js
ac.grant('editor').execute('publish').on('article');
let permission = ac.can('editor').execute('publish').sync().on('article'); // <-- Sync Example
let permission = await ac.can('editor').execute('publish').on('article'); // <-- Async Example
console(permission.attributes); // —> ['*'] (all attributes)
console(permission.granted); // -> true

ac.grant('sports/editor').execute('publish').when({Fn: 'EQUALS', args: {category: 'sports'}}).on('article');
permission = ac.can('sports/editor').execute('publish').with({category: 'sports'}).sync().on('article'); // <-- Sync Example
permission = await ac.can('sports/editor').execute('publish').with({category: 'sports'}).on('article'); // <-- Async Example
console(permission.attributes); // —> ['*'] (all attributes)
console(permission.granted); // -> true

permission = ac.can('sports/editor').execute('publish').with({category: 'politics'})).sync().on('article'); // <-- Sync Example
permission = await ac.can('sports/editor').execute('publish').with({category: 'politics'})).on('article'); // <-- Async Example
console(permission.attributes); // -> []
console(permission.granted); // -> false
```

### Resources and Resource-Attributes

Multiple roles can have access to a specific resource. But depending on the context, you may need to limit the contents of the resource for specific roles.  

This is possible by resource attributes. You can use Glob notation to define allowed or denied attributes.

For example, we have a `video` resource that has the following attributes: `id`, `title` and `runtime`.
All attributes of *any* `video` resource can be read by an `admin` role:
```js
ac.grant('admin').execute('read').on('video', ['*']);
// equivalent to:
// ac.grant('admin').execute('read').on('video');
```
But the `id` attribute should not be read by a `user` role.  
```js
ac.grant('user').execute('read').on('video', ['*', '!id']);
// equivalent to:
// ac.grant('user').execute('read').on('video', ['title', 'runtime']);
```

You can also use nested objects (attributes).
```js
ac.grant('user').execute('read').on('account', ['*', '!record.id']);
```

### Checking Permissions and Filtering Attributes

You can call `.can(<role>).<action>(<resource>)` on an `AccessControl` instance to check for granted permissions for a specific resource and action.

```js
const permission = ac.can('user').execute('read').on('account');
permission.granted;       // true
permission.attributes;    // ['*', '!record.id']
permission.filter(data);  // filtered data (without record.id)
```
See [express.js example](#expressjs-example).

### Defining All Grants at Once

You can pass the grants directly to the `AccessControl` constructor.
It accepts either an `Object`:

```js
// This is actually how the grants are maintained internally.
let grantsObject = {
    admin: {
        grants: [
            {
                resource: 'video', action: '*', attributes: ['*']
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
            },
        ]
    },
    "sports/editor": {
        grants: [
            {
                resource: 'article',
                action: '*',
                attributes: ["*"],
                condition: {
                    Fn: 'EQUALS',
                    args: {
                        'category': 'sports'
                    }
                }
            }   
        ] 
    },
    "sports/writer": {
        grants: [
            {
                resource: 'article',
                action: ['create', 'update'],
                attributes: ["*", "!status"],
                condition: {
                    Fn: 'EQUALS',
                    args: {
                        'category': 'sports'
                    }
                }
            }   
        ] 
    }
};

const ac = new AccessControl(grantsObject);
```
... or an `Array` (useful when fetched from a database):
```js
// grant list fetched from Database (to be converted to a valid grants object, internally)
let grantList = [
    { role: 'admin', resource: 'video', action: 'create', attributes: ['*'] },
    { role: 'admin', resource: 'video', action: 'read', attributes: ['*'] },
    { role: 'admin', resource: 'video', action: 'update', attributes: ['*'] },
    { role: 'admin', resource: 'video', action: 'delete', attributes: ['*'] },

    { role: 'user', resource: 'video', action: 'create', attributes: ['*'] },
    { role: 'user', resource: 'video', action: 'read', attributes: ['*'] },
    { role: 'user', resource: 'video', action: 'update', attributes: ['*'] },
    { role: 'user', resource: 'video', action: 'delete', attributes: ['*'] },
    { role: 'user', resource: 'photo', action: '*', attributes: ['*'] },
    { role: 'user', resource: 'article', action: ['*', '!delete'], attributes: ['*'] },
    { role: 'sports/editor', resource: 'article', action: 'create', attributes: ['*'],
      condition: { "Fn": "EQUALS", "args": { "category": "sports" } }
    },
    {
        role: 'sports/editor', resource: 'article', action: 'update', attributes: ['*'],
        condition: { "Fn": "EQUALS", "args": { "category": "sports" } }
    }
];
const ac = new AccessControl(grantList);
```
You can set/get grants any time:
```js
const ac = new AccessControl();
ac.setGrants(grantsObject);
console.log(ac.getGrants());
// You can save ac.getGrants() to Database
// Please note: User should be part of your code and wraps calls to User to table/collection.
await User.save({permissions: acl.toJSON()}); 
// Retrieve from DB
const perms = await User.getBydId(userId);
ac = AccessControl.fromJSON(user.permissions);

// if your DB supports storing JSON natively then you can use following code.
await User.save({permissions: acl.getGrants()}); 
// Retrieve from DB
const perms = await User.getBydId(userId);
ac.setGrants(user.permissions);
```

### Extending Roles
```js
const ac = new AccessControl();
const editorGrant = {
    role: 'editor',
    resource: 'post',
    action: 'create', // action
    attributes: ['*'] // grant only
};
ac.grant(editorGrant);
// first level of extension (extending with condition)
ac.extendRole('sports/editor', 'editor', {Fn: 'EQUALS', args: {category: 'sports'}});
ac.extendRole('politics/editor', 'editor', {Fn: 'EQUALS', args: {category: 'politics'}}); 


let permission = ac.can('sports/editor').context({category: 'sports'}).execute('create').sync().on('post'); // <-- Sync Example
let permission = await ac.can('sports/editor').context({category: 'sports'}).execute('create').on('post'); // <-- Async Example
console.log(permission.granted);    // —> true
console.log(permission.attributes); // —> ['*']

permission = ac.can('sports/editor').context({category: 'politics'}).execute('create').sync().on('post'); // <-- Sync Example
permission = await ac.can('sports/editor').context({category: 'politics'}).execute('create').on('post'); // <-- Async Example
console.log(permission.granted);    // —> false
console.log(permission.attributes); // —> []

// second level of extension (extending without condition)
ac.extendRole('sports-and-politics/editor', ['sports/editor', 'politics/editor']);
permission = ac.can('sports-and-politics/editor').context({category: 'politics'}).execute('create').sync().on('post'); // <-- Sync Example
permission = await ac.can('sports-and-politics/editor').context({category: 'politics'}).execute('create').on('post'); // <-- Async Example
console.log(permission.granted);    // —> true
console.log(permission.attributes); // —> ['*']

// third level of extension (extending with condition)
ac.extendRole('conditional/sports-and-politics/editor', 'sports-and-politics/editor', {
    Fn: 'EQUALS',
    args: { status: 'draft' }
}); // <-- Async Example

permission = ac.can('conditional/sports-and-politics/editor').context({category: 'politics', status: 'draft'}).execute('create').sync().on('post'); // <-- Sync Example
permission = await ac.can('conditional/sports-and-politics/editor').context({category: 'politics', status: 'draft'}).execute('create').on('post'); // <-- Async Example
console.log(permission.granted);    // —> true
console.log(permission.attributes); // —> ['*']

permission = ac.can('conditional/sports-and-politics/editor').context({category: 'politics', status: 'published'}).execute('create').sync().on('post'); // <-- Sync Example
permission = await ac.can('conditional/sports-and-politics/editor').context({category: 'politics', status: 'published'}).execute('create').on('post'); // <-- Async Example
console.log(permission.granted);    // —> false
console.log(permission.attributes); // —> []
```

### Allowed Resources and actions
```js
const ac = new AccessControl();
ac.grant('user').condition({Fn: 'EQUALS', args: {category: 'sports'}}).execute('create').on('article');
ac.grant('user').execute('*').on('image');
ac.extendRole('admin', 'user');

ac.grant('admin').execute('delete').on('article');        
ac.grant('admin').execute('*').on('category');
ac.extendRole('owner', 'admin'); // <-- Sync Example

ac.grant('owner').execute('*').on('video');

console.log(ac.allowedResourcesSync({role: 'user'}).sort()); // -> ['article', 'image'] 
console.log(await ac.allowedResources({role: 'user'}).sort()); // -> ['article', 'image'] 
console.log(ac.allowedResourcesSync({role: 'user', context: {category: 'politics'}}).sort()); // -> ['image']      
console.log(await ac.allowedResources({role: 'user', context: {category: 'politics'}}).sort()); // -> ['image']
console.log(ac.allowedResourcesSync({role: 'admin'}).sort()); // -> ['article', 'category', 'image']
console.log(await ac.allowedResources({role: 'admin'}).sort()); // -> ['article', 'category', 'image']
console.log(ac.allowedResourcesSync({role: 'owner'}).sort()); // -> ['article', 'category', 'image', 'video']
console.log(await ac.allowedResources({role: 'owner'}).sort()); // -> ['article', 'category', 'image', 'video']
console.log(ac.allowedResourcesSync({role: ['admin', 'owner']}).sort()); // -> ['article', 'category', 'image', 'video']
console.log(await ac.allowedResources({role: ['admin', 'owner']}).sort()); // -> ['article', 'category', 'image', 'video']

console.log(ac.allowedActionsSync({role: 'user', resource: 'article'}).sort()); // -> ['create']
console.log(await ac.allowedActions({role: 'user', resource: 'article'}).sort()); // -> ['create']
console.log(ac.allowedActionsSync({role: 'user', resource: 'article', context: {category: 'politics'}})); // -> []        
console.log(await ac.allowedActions({role: 'user', resource: 'article', context: {category: 'politics'}})); // -> []        
console.log(ac.allowedActionsSync({role: ['admin', 'user'], resource: 'article'}).sort()); // -> ['create', 'delete']
console.log(await ac.allowedActions({role: ['admin', 'user'], resource: 'article'}).sort()); // -> ['create', 'delete']
console.log(ac.allowedActionsSync({role: 'admin', resource: 'category'}).sort()); // -> ['*']
console.log(await ac.allowedActions({role: 'admin', resource: 'category'}).sort()); // -> ['*']
console.log(ac.allowedActionsSync({role: 'owner', resource: 'video'}).sort()); // -> ['*']
console.log(await ac.allowedActions({role: 'owner', resource: 'video'}).sort()); // -> ['*']

```
**NOTE:**  allowedResources and allowedActions skip the conditions when context is not passed

### Example for versions >= 4.0.0
[Take a look at the test cases][tests]

## Upgrading to >= 4.0.0
* There are many breaking changes so please update the code accordingly.
* All future updates and bug fixes will happen only to versions >= 4.
* New features only available in >= 4
  * Storing and retrieving of custom condition functions.
  * Promise based conditional functions.
  * For Sync use cases use function with Sync suffix.

## Licenses

* [role-acl][this]: [MIT][license].
* [AccessControl][onury-accesscontrol]: [MIT][onury-accesscontrol-license].

[rbac]:https://en.wikipedia.org/wiki/Role-based_access_control
[abac]:https://en.wikipedia.org/wiki/Attribute-Based_Access_Control
[crud]:https://en.wikipedia.org/wiki/Create,_read,_update_and_delete
[nist-paper]:http://csrc.nist.gov/groups/SNS/rbac/documents/kuhn-coyne-weil-10.pdf
[this]:https://github.com/tensult/role-acl
[onury-accesscontrol]: https://github.com/onury/accesscontrol
[license]:https://github.com/tensult/role-acl/blob/master/LICENSE
[onury-accesscontrol-license]:https://github.com/onury/accesscontrol/blob/master/LICENSE
[tests]:https://github.com/tensult/role-acl/blob/master/test/acl.spec.ts

## Contact us
This product is supported and actively developed by [Tensult](https://wwww/tensult.com). You can contact us at info@tensult.com.

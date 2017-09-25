Role, Attribute and conditions based Access Control for Node.js  

`npm i role-acl --save`  

Many [RBAC][rbac] (Role-Based Access Control) implementations differ, but the basics is widely adopted since it simulates real life role (job) assignments. But while data is getting more and more complex; you need to define policies on resources, subjects or even environments. This is called [ABAC][abac] (Attribute-Based Access Control).

With the idea of merging the best features of the two (see this [NIST paper][nist-paper]); this library implements RBAC basics and also focuses on *resource*, *action* attributes and conditions.

This library is an extension of [AccessControl][onury-accesscontrol]. But I removed support for deny statements from orginal implementation.

### Core Features

- Chainable, friendly API.  
e.g. `ac.can(role).createOwn(resource)`
- Role hierarchical inheritance.
- Define grants at once (e.g. from database result) or one by one.
- Grant permissions by attributes defined by glob notation (with nested object support).
- Ability to filter data (model) instance by allowed attributes.
- Ability to control access on "own" or "any" resources.
- Ability to control access using conditions.
- Supports AND, OR, NOT, EQUALS, NOT_EQUALS, STARTS_WITH, LIST_CONTAINS conditions
- Policies are JSON compatible so can be stored and retrieved from database.
- Fast. (Grants are stored in memory, no database queries.)
- TypeScript support.

## Guide

```js
const AccessControl = require('role-acl');
// or:
// import { AccessControl } from 'role-acl';
```

### Basic Example

Define roles and grants one by one.
```js
const ac = new AccessControl();
ac.grant('user')                    // define new or modify existing role. also takes an array.
    .createOwn('video')             // equivalent to .createOwn('video', ['*'])
    .deleteOwn('video')
    .readAny('video')
  .grant('admin')                   // switch to another role without breaking the chain
    .extend('user')                 // inherit role capabilities. also takes an array
    .updateAny('video', ['title'])  // explicitly defined attributes
    .deleteAny('video');

const permission = ac.can('user').createOwn('video');
console.log(permission.granted);    // —> true
console.log(permission.attributes); // —> ['*'] (all attributes)

permission = ac.can('admin').updateAny('video');
console.log(permission.granted);    // —> true
console.log(permission.attributes); // —> ['title']
```

### Conditions Examples

Define roles and grants one by one.
```js
const ac = new AccessControl();
ac.grant('user').condition(
    {
        Fn: 'EQUALS',
        args: {
            'category': 'sports'
        }
    }).createAny('article');

let permission = ac.can('user').context({ category: 'sports' }).createAny('article');
console.log(permission.granted);    // —> true
console.log(permission.attributes); // —> ['*'] (all attributes)

permission = ac.can('user').context({ category: 'tech' }).createAny('article');
console.log(permission.granted);    // —> false
console.log(permission.attributes); // —> []
```

### Express.js Example

Check role permissions for the requested resource and action, if granted; respond with filtered attributes.

```js
const ac = new AccessControl(grants);
// ...
router.get('/videos/:title', function (req, res, next) {
    const permission = ac.can(req.user.role).readAny('video');
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

[CRUD][crud] operations are the actions you can perform on a resource. There are two action-attributes which define the **possession** of the resource: *own* and *any*.

For example, an `admin` role can `create`, `read`, `update` or `delete` (CRUD) **any** `account` resource. But a `user` role might only `read` or `update` its **own** `account` resource.

<table>
    <thead>
        <tr>
            <th>Action</th>
            <th>Possession</th>
        </tr>
    </thead>
    <tbody>
        <tr>
            <td rowspan="2">
            <b>C</b>reate<br />
            <b>R</b>ead<br />
            <b>U</b>pdate<br />
            <b>D</b>elete<br />
            </td>
            <td>Own</td>
            <td>The C|R|U|D action is (or not) to be performed on own resource(s) of the current subject.</td>
        </tr>
        <tr>
            <td>Any</td>
            <td>The C|R|U|D action is (or not) to be performed on any resource(s); including own.</td>
        </tr>   
    </tbody>
</table>

```js
ac.grant('role').readOwn('resource');
```

### Custom Actions
Along with CRUD actions we can define custom actions.

```js
ac.grant('editor').execute('publish').on('article');
let permission = ac.can('editor').execute('publish').on('article');
console(permission.attributes); // —> ['*'] (all attributes)
console(permission.granted); // -> true

ac.grant('sports/editor').execute('publish').when({Fn: 'EQUALS', args: {category: 'sports'}}).on('article');
permission = ac.can('sports/editor').execute('publish').with({category: 'sports'}).on('article');
console(permission.attributes); // —> ['*'] (all attributes)
console(permission.granted); // -> true

permission = ac.can('sports/editor').execute('publish').with({category: 'politics'})).on('article');
console(permission.attributes).toEqual([]);
console(permission.granted).toEqual(false);

ac.grant({
    role: 'politics/editor',
    action: 'publish',
    resource: 'article',
    condition: {Fn: 'EQUALS', args: {category: 'politics'}},
    attributes: attrs
});
permission = ac.can('politics/editor').execute('publish').with({category: 'politics'}).on('article');
console(permission.attributes).toEqual(attrs);
console(permission.granted).toEqual(true);
```

### Resources and Resource-Attributes

Multiple roles can have access to a specific resource. But depending on the context, you may need to limit the contents of the resource for specific roles.  

This is possible by resource attributes. You can use Glob notation to define allowed or denied attributes.

For example, we have a `video` resource that has the following attributes: `id`, `title` and `runtime`.
All attributes of *any* `video` resource can be read by an `admin` role:
```js
ac.grant('admin').readAny('video', ['*']);
// equivalent to:
// ac.grant('admin').readAny('video');
```
But the `id` attribute should not be read by a `user` role.  
```js
ac.grant('user').readOwn('video', ['*', '!id']);
// equivalent to:
// ac.grant('user').readOwn('video', ['title', 'runtime']);
```

You can also use nested objects (attributes).
```js
ac.grant('user').readOwn('account', ['*', '!record.id']);
```

### Checking Permissions and Filtering Attributes

You can call `.can(<role>).<action>(<resource>)` on an `AccessControl` instance to check for granted permissions for a specific resource and action.

```js
const permission = ac.can('user').readOwn('account');
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
        video: {
            'create:any': ['*'],
            'read:any': ['*'],
            'update:any': ['*'],
            'delete:any': ['*']
        }
    },
    user: {
        video: {
            'create:own': ['*'],
            'read:own': ['*'],
            'update:own': ['*'],
            'delete:own': ['*']
        }
    },
    "sports/editor": {
        article: {
            "create:any": [
                {
                    attributes: ["*"],
                    condition: {
                        Fn: 'EQUALS',
                        args: {
                            'category': 'sports'
                        }
                    }
                }
            ],
            "update:any": [
                {
                    attributes: ["*"],
                    condition: {
                        Fn: 'EQUALS',
                        args: {
                            'category': 'sports'
                        }
                    }
                }
            ]
        }
    },
    "sports/writer": {
        article: {
            "create:any": [
                {
                    attributes: ["*", "!status"],
                    condition: {
                        Fn: 'EQUALS',
                        args: {
                            'category': 'sports'
                        }
                    }
                }
            ],
            "update:any": [
                {
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
    }
};

const ac = new AccessControl(grantsObject);
```
... or an `Array` (useful when fetched from a database):
```js
// grant list fetched from DB (to be converted to a valid grants object, internally)
let grantList = [
    { role: 'admin', resource: 'video', action: 'create:any', attributes: ['*'] },
    { role: 'admin', resource: 'video', action: 'read:any', attributes: ['*'] },
    { role: 'admin', resource: 'video', action: 'update:any', attributes: ['*'] },
    { role: 'admin', resource: 'video', action: 'delete:any', attributes: ['*'] },

    { role: 'user', resource: 'video', action: 'create:own', attributes: ['*'] },
    { role: 'user', resource: 'video', action: 'read:any', attributes: ['*'] },
    { role: 'user', resource: 'video', action: 'update:own', attributes: ['*'] },
    { role: 'user', resource: 'video', action: 'delete:own', attributes: ['*'] },

    { role: 'sports/editor', resource: 'article', action: 'create:any', attributes: ['*'],
      condition: { "Fn": "EQUALS", "args": { "category": "sports" } }
    },
    {
        role: 'sports/editor', resource: 'article', action: 'update:any', attributes: ['*'],
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
```

### Extending Roles
```js
const ac = new AccessControl();
const editorGrant = {
    role: 'editor',
    resource: 'post',
    action: 'create:any', // action:possession
    attributes: ['*'] // grant only
};
ac.grant(editorGrant);
// first level of extension (extending with condition)
ac.extendRole('sports/editor', 'editor', {Fn: 'EQUALS', args: {category: 'sports'}});
ac.extendRole('politics/editor', 'editor', {Fn: 'EQUALS', args: {category: 'politics'}});

let permission = ac.can('sports/editor').context({category: 'sports'}).createAny('post');
console.log(permission.granted);    // —> true
console.log(permission.attributes); // —> ['*']

permission = ac.can('sports/editor').context({category: 'politics'}).createAny('post');
console.log(permission.granted);    // —> false
console.log(permission.attributes); // —> []

// second level of extension (extending without condition)
ac.extendRole('sports-and-politics/editor', ['sports/editor', 'politics/editor']);
permission = ac.can('sports-and-politics/editor').context({category: 'politics'}).createAny('post');
console.log(permission.granted);    // —> true
console.log(permission.attributes); // —> ['*']

// third level of extension (extending with condition)
ac.extendRole('conditonal/sports-and-politics/editor', 'sports-and-politics/editor', {
    Fn: 'EQUALS',
    args: { status: 'draft' }
});
permission = ac.can('conditonal/sports-and-politics/editor').context({category: 'politics', status: 'draft'}).createAny('post');
console.log(permission.granted);    // —> true
console.log(permission.attributes); // —> ['*']

permission = ac.can('conditonal/sports-and-politics/editor').context({category: 'politics', status: 'published'}).createAny('post');
console.log(permission.granted);    // —> false
console.log(permission.attributes); // —> []
```
### Read more
[More Examples][tests]

## License

[MIT][license].

[rbac]:https://en.wikipedia.org/wiki/Role-based_access_control
[abac]:https://en.wikipedia.org/wiki/Attribute-Based_Access_Control
[crud]:https://en.wikipedia.org/wiki/Create,_read,_update_and_delete
[nist-paper]:http://csrc.nist.gov/groups/SNS/rbac/documents/kuhn-coyne-weil-10.pdf
[onury-accesscontrol]: https://github.com/onury/accesscontrol
[license]:https://github.com/tensult/role-acl/blob/master/LICENSE
[tests]:https://github.com/tensult/role-acl/blob/master/test/ac.spec.js

const AccessControl = require("./index");
const matcher = require("matcher");

AccessControl.isAllowed = function (account, user, resource, action, context) {
    const acl = new AccessControl(account.acl);
    const permission = acl.permission({
        resource,
        action,
        role: user.policy.roles,
        context
    });
    return permission.granted;
}

AccessControl.getAllowedAttributes = function (account, user, resource, action, context) {
    const acl = new AccessControl(account.acl);
    const permission = acl.permission({
        resource,
        action,
        role: user.policy.roles,
        context
    });
    return permission.attributes;
}

AccessControl.allowedResources = function (account, user) {
    const acl = new AccessControl(account.acl);
    const permittedResources = acl.allowedResources({
        role: user.policy.roles
    });
    return matcher(Object.keys(account.permissions), permittedResources);
}

AccessControl.allowedActions = function (account, user, resource) {
    const acl = new AccessControl(account.acl);
    const permittedActions = acl.allowedActions({
        role: user.policy.roles,
        resource
    });
    return matcher(account.permissions[resource], permittedActions);
}

AccessControl.allowedCategories = function (account, user, resource, action) {
    const acl = new AccessControl(account.acl);
    const permittedCategories = acl.permission({
        role: user.policy.roles,
        resource: "category",
        action: "search"
    }).attributes;
    if (permittedCategories.length === 1 && permittedCategories[0] === "*") {
        return permittedCategories;
    }
    return permittedCategories.filter((category => {
        return acl.permission({
            role: user.policy.roles,
            resource,
            action,
            context: {
                category
            }
        }).granted;
    }));
}

window.AccessControl = AccessControl;

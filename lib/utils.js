"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
// dep modules
var Notation = require("notation");
// own modules
var core_1 = require("./core");
var condtions_1 = require("./condtions");
var utils = {
    type: function (o) {
        return Object.prototype.toString.call(o).match(/\s(\w+)/i)[1].toLowerCase();
    },
    hasDefined: function (o, propName) {
        return o.hasOwnProperty(propName) && o[propName] !== undefined;
    },
    toStringArray: function (value) {
        if (Array.isArray(value))
            return value;
        if (typeof value === 'string')
            return value.trim().split(/\s*[;,]\s*/);
        // throw new Error('Cannot convert value to array!');
        return null;
    },
    toArray: function (value) {
        if (Array.isArray(value))
            return value;
        return [value];
    },
    isFilledStringArray: function (arr) {
        if (!arr || !Array.isArray(arr))
            return false;
        for (var _i = 0, arr_1 = arr; _i < arr_1.length; _i++) {
            var s = arr_1[_i];
            if (typeof s !== 'string' || s.trim() === '')
                return false;
        }
        return true;
    },
    isStringOrArray: function (value) {
        return typeof value === 'string' || utils.isFilledStringArray(value);
    },
    isEmptyArray: function (value) {
        return Array.isArray(value) && value.length === 0;
    },
    uniqConcat: function (arrA, arrB) {
        var arr = arrA.concat();
        arrB.forEach(function (b) {
            if (arr.indexOf(b) < 0)
                arr.push(b);
        });
        return arr;
    },
    subtractArray: function (arrA, arrB) {
        return arrA.concat().filter(function (a) { return arrB.indexOf(a) === -1; });
    },
    eachKey: function (o, callback) {
        return Object.keys(o).forEach(callback);
    },
    /**
     *  Gets roles and extended roles in a flat array.
     */
    getFlatRoles: function (grants, roles, context) {
        roles = utils.toStringArray(roles);
        if (!roles)
            throw new core_1.AccessControlError("Invalid role(s): " + JSON.stringify(roles));
        var arr = roles.concat();
        roles.forEach(function (roleName) {
            var role = grants[roleName];
            if (!role)
                throw new core_1.AccessControlError("Role not found: \"" + roleName + "\"");
            if (Array.isArray(role.$extend)) {
                var rolesMetCondition = role.$extend.filter(function (roleCondition) {
                    return condtions_1.conditionEvaluator(roleCondition.condition, context);
                }).map(function (roleCondition) {
                    return roleCondition.role;
                });
                arr = utils.uniqConcat(arr, utils.getFlatRoles(grants, rolesMetCondition, context));
            }
        });
        return arr;
    },
    normalizeAction: function (info) {
        // validate and normalize action
        if (typeof info.action !== 'string') {
            throw new core_1.AccessControlError("Invalid action: " + info.action);
        }
        return info;
    },
    normalizeQueryInfo: function (query, all) {
        if (all === void 0) { all = false; }
        // clone the object
        query = Object.assign({}, query);
        // validate and normalize role(s)
        query.role = utils.toStringArray(query.role);
        if (!utils.isFilledStringArray(query.role)) {
            throw new core_1.AccessControlError("Invalid role(s): " + JSON.stringify(query.role));
        }
        // validate resource
        if (typeof query.resource !== 'string' || query.resource.trim() === '') {
            throw new core_1.AccessControlError("Invalid resource: \"" + query.resource + "\"");
        }
        query.resource = query.resource.trim();
        // this part is not necessary if this is invoked from a comitter method
        // such as `createAny()`. So we'll check if we need to validate all
        // properties such as `action`.
        if (all)
            query = utils.normalizeAction(query);
        return query;
    },
    normalizeAccessInfo: function (access, all) {
        if (all === void 0) { all = false; }
        // clone the object
        access = Object.assign({}, access);
        // validate and normalize role(s)
        access.role = utils.toStringArray(access.role);
        if (!utils.isFilledStringArray(access.role)) {
            throw new core_1.AccessControlError("Invalid role(s): " + JSON.stringify(access.role));
        }
        // validate and normalize resource
        access.resource = utils.toStringArray(access.resource);
        if (!utils.isFilledStringArray(access.resource)) {
            throw new core_1.AccessControlError("Invalid resource(s): " + JSON.stringify(access.resource));
        }
        access.attributes = !access.attributes ? ['*'] : utils.toStringArray(access.attributes);
        // this part is not necessary if this is invoked from a comitter method
        // such as `createAny()`. So we'll check if we need to validate all
        // properties such as `action`.
        if (all)
            access = utils.normalizeAction(access);
        return access;
    },
    /**
     *  Used to re-set (prepare) the `attributes` of an `IAccessInfo` object
     *  when it's first initialized with e.g. `.grant()` or `.deny()` chain
     *  methods.
     *  @param {IAccessInfo} access
     *  @returns {IAccessInfo}
     */
    resetAttributes: function (access) {
        if (!access.attributes || utils.isEmptyArray(access.attributes)) {
            access.attributes = ['*'];
        }
        return access;
    },
    /**
     *  Checks whether the given access info can be commited to grants model.
     *  @param {IAccessInfo|IQueryInfo} info
     *  @returns {Boolean}
     */
    isInfoFulfilled: function (info) {
        return utils.hasDefined(info, 'role')
            && utils.hasDefined(info, 'action')
            && utils.hasDefined(info, 'resource');
    },
    /**
     *  Commits the given `IAccessInfo` object to the grants model.
     *  CAUTION: if attributes is omitted, it will default to `['*']` which
     *  means "all attributes allowed".
     *  @param {Any} grants
     *  @param {IAccessInfo} access
     *  @param {Boolean} normalizeAll
     *         Specifies whether to validate and normalize all properties of
     *         the inner `IAccessInfo` object, including `action`.
     *  @throws {Error} If `IAccessInfo` object fails validation.
     */
    commitToGrants: function (grants, access, normalizeAll) {
        if (normalizeAll === void 0) { normalizeAll = false; }
        access = utils.normalizeAccessInfo(access, normalizeAll);
        // console.log(access);
        // grant.role also accepts an array, so treat it like it.
        access.role.forEach(function (role) {
            if (!grants.hasOwnProperty(role))
                grants[role] = {};
            var grantItem = grants[role];
            var action = access.action;
            access.resource.forEach(function (res) {
                grantItem[res] = grantItem[res] || {};
                grantItem[res][action] = grantItem[res][action] || [];
                grantItem[res][action].push({
                    attributes: access.attributes,
                    condition: access.condition
                });
            });
        });
    },
    /**
     *  When more than one role is passed, we union the permitted attributes
     *  for all given roles; so we can check whether "at least one of these
     *  roles" have the permission to execute this action.
     *  e.g. `can(['admin', 'user']).createAny('video')`
     *
     *  @param {Any} grants
     *  @param {IQueryInfo} query
     *
     *  @returns {Array<String>} - Array of union'ed attributes.
     */
    getUnionConditionalAttrsOfRoles: function (grants, query) {
        if (!grants) {
            throw new core_1.AccessControlError('Grants are not set.');
        }
        // throws if has any invalid property value
        query = utils.normalizeQueryInfo(query);
        var attrsList = [];
        // get roles and extended roles in a flat array
        var roles = utils.getFlatRoles(grants, query.role, query.context);
        // iterate through roles and add permission attributes (array) of
        // each role to attrsList (array).
        roles.forEach(function (role, index) {
            var grantItem = grants[role];
            if (grantItem) {
                var resource = grantItem[query.resource];
                if (resource) {
                    var actionAttrs = resource[query.action];
                    if (actionAttrs && actionAttrs.length) {
                        attrsList = attrsList.concat(actionAttrs);
                    }
                }
            }
        });
        return attrsList;
    },
    /**
     *  Checks the given grants model and gets an array of non-existent roles
     *  from the given roles.
     *  @param {Any} grants - Grants model to be checked.
     *  @param {Array<string>} roles - Roles to be checked.
     *  @returns {Array<String>} - Array of non-existent roles. Empty array if
     *  all exist.
     */
    getNonExistentRoles: function (grants, roles) {
        var non = [];
        for (var _i = 0, roles_1 = roles; _i < roles_1.length; _i++) {
            var role = roles_1[_i];
            if (!grants.hasOwnProperty(role))
                non.push(role);
        }
        return non;
    },
    /**
     *  Extends the given role(s) with privileges of one or more other roles.
     *
     *  @param {Any} grants
     *  @param {String|Array<String>} roles
     *         Role(s) to be extended.
     *         Single role as a `String` or multiple roles as an `Array`.
     *         Note that if a role does not exist, it will be automatically
     *         created.
     *
     *  @param {String|Array<String>} extenderRoles
     *         Role(s) to inherit from.
     *         Single role as a `String` or multiple roles as an `Array`.
     *         Note that if a extender role does not exist, it will throw.
     *  @param {ICondition} [condition]
     *         Condition to be used for extension of roles. Only extends
     *         the roles when condition is met
     *
     *  @throws {Error}
     *          If a role is extended by itself or a non-existent role.
     */
    extendRole: function (grants, roles, extenderRoles, condition) {
        var arrExtRoles = utils.toStringArray(extenderRoles);
        if (!arrExtRoles)
            throw new core_1.AccessControlError("Invalid extender role(s): " + JSON.stringify(extenderRoles));
        var nonExistentExtRoles = utils.getNonExistentRoles(grants, arrExtRoles);
        if (nonExistentExtRoles.length > 0) {
            throw new core_1.AccessControlError("Cannot extend with non-existent role(s): \"" + nonExistentExtRoles.join(', ') + "\"");
        }
        roles = utils.toStringArray(roles);
        if (!roles)
            throw new core_1.AccessControlError("Invalid role(s): " + JSON.stringify(roles));
        roles.forEach(function (role) {
            if (arrExtRoles.indexOf(role) >= 0) {
                throw new core_1.AccessControlError("Attempted to extend role \"" + role + "\" by itself.");
            }
            grants[role] = grants[role] || {};
            grants[role].$extend = grants[role].$extend || [];
            grants[role].$extend = grants[role].$extend.concat(arrExtRoles.map(function (extRole) {
                return {
                    role: extRole,
                    condition: condition
                };
            }));
        });
    },
    matchesAllElement: function (values, predicateFn) {
        values = utils.toArray(values);
        return values.every(predicateFn);
    },
    matchesAnyElement: function (values, predicateFn) {
        values = utils.toArray(values);
        return values.some(predicateFn);
    },
    filter: function (object, attributes) {
        if (!Array.isArray(attributes) || attributes.length === 0) {
            return {};
        }
        var notation = new Notation(object);
        return notation.filter(attributes).value;
    },
    filterAll: function (arrOrObj, attributes) {
        if (!Array.isArray(arrOrObj)) {
            return utils.filter(arrOrObj, attributes);
        }
        return arrOrObj.map(function (o) {
            return utils.filter(o, attributes);
        });
    }
};
exports.default = utils;

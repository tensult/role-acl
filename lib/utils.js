"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
// dep modules
var Notation = require("notation");
var MicroMatch = require("micromatch");
// own modules
var core_1 = require("./core");
var condtions_1 = require("./condtions");
var utils = {
    clone: function (o) {
        return JSON.parse(JSON.stringify(o));
    },
    type: function (o) {
        return Object.prototype.toString.call(o).match(/\s(\w+)/i)[1].toLowerCase();
    },
    hasDefined: function (o, propName) {
        return o.hasOwnProperty(propName) && o[propName] !== undefined;
    },
    toStringArray: function (value) {
        if (Array.isArray(value))
            return value.slice();
        if (typeof value === 'string')
            return value.trim().split(/\s*[;,]\s*/);
        // throw new Error('Cannot convert value to array!');
        return null;
    },
    toArray: function (value) {
        if (Array.isArray(value))
            return value.slice();
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
        var arr = arrA.slice();
        arrB.forEach(function (b) {
            if (arr.indexOf(b) < 0)
                arr.push(b);
        });
        return arr;
    },
    subtractArray: function (arrA, arrB) {
        return arrA.slice().filter(function (a) { return arrB.indexOf(a) === -1; });
    },
    eachKey: function (o, callback) {
        return Object.keys(o).forEach(callback);
    },
    /**
     *  Gets roles and extended roles in a flat array.
     */
    getFlatRoles: function (grants, roles, context, skipConditions) {
        roles = utils.toStringArray(roles);
        if (!roles)
            throw new core_1.AccessControlError("Invalid role(s): " + JSON.stringify(roles));
        var arr = roles.slice();
        roles.forEach(function (roleName) {
            var roleItem = grants[roleName];
            if (!roleItem)
                throw new core_1.AccessControlError("Role not found: \"" + roleName + "\"");
            if (roleItem.$extend) {
                var rolesMetCondition = Object.keys(roleItem.$extend).filter(function (role) {
                    return skipConditions || condtions_1.conditionEvaluator(roleItem.$extend[role].condition, context);
                });
                arr = utils.uniqConcat(arr, utils.getFlatRoles(grants, rolesMetCondition, context, skipConditions));
            }
        });
        return arr;
    },
    normalizeGrantsObject: function (grants) {
        var grantsCopy = utils.clone(grants);
        for (var role in grantsCopy) {
            if (!grantsCopy[role].grants) {
                continue;
            }
            grantsCopy[role].grants.forEach(function (grant) {
                grant.attributes = grant.attributes || ['*'];
            });
            grantsCopy[role].score = grantsCopy[role].score || 1;
        }
        return grantsCopy;
    },
    normalizeQueryInfo: function (query) {
        // clone the object
        query = Object.assign({}, query);
        // validate and normalize role(s)
        query.role = utils.toStringArray(query.role);
        if (!utils.isFilledStringArray(query.role)) {
            throw new core_1.AccessControlError("Invalid role(s): " + JSON.stringify(query.role));
        }
        // validate resource
        if (query.resource) {
            if (typeof query.resource !== 'string' || query.resource.trim() === '') {
                throw new core_1.AccessControlError("Invalid resource: \"" + query.resource + "\"");
            }
            query.resource = query.resource.trim();
        }
        // validate action
        if (query.action) {
            if (typeof query.action !== 'string' || query.action.trim() === '') {
                throw new core_1.AccessControlError("Invalid action: " + query.action);
            }
        }
        return query;
    },
    normalizeAccessInfo: function (access) {
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
        // validate and normalize resource
        access.action = utils.toStringArray(access.action);
        if (!utils.isFilledStringArray(access.action)) {
            throw new core_1.AccessControlError("Invalid resource(s): " + JSON.stringify(access.action));
        }
        access.attributes = !access.attributes ? ['*'] : utils.toStringArray(access.attributes);
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
     *  @throws {Error} If `IAccessInfo` object fails validation.
     */
    commitToGrants: function (grants, access) {
        access = utils.normalizeAccessInfo(access);
        access.role.forEach(function (role) {
            grants[role] = grants[role] || { score: 1 };
            grants[role].grants = grants[role].grants || [];
            grants[role].grants.push({
                resource: access.resource,
                action: access.action,
                attributes: access.attributes,
                condition: access.condition
            });
        });
    },
    getUnionGrantsOfRoles: function (grants, query) {
        if (!grants) {
            throw new core_1.AccessControlError('Grants are not set.');
        }
        // throws if has any invalid property value
        query = utils.normalizeQueryInfo(query);
        // get roles and extended roles in a flat array
        var roles = utils.getFlatRoles(grants, query.role, query.context, query.skipConditions);
        // iterate through roles and add permission attributes (array) of
        // each role to attrsList (array).
        return roles.filter(function (role) {
            return grants[role] && grants[role].grants;
        }).map(function (role) {
            return grants[role].grants;
        }).reduce(function (allGrants, roleGrants) {
            return allGrants.concat(roleGrants);
        }, []);
    },
    getUnionResourcesOfRoles: function (grants, query) {
        query.skipConditions = query.skipConditions || !query.context;
        return utils.getUnionGrantsOfRoles(grants, query)
            .filter(function (grant) {
            return query.skipConditions || condtions_1.conditionEvaluator(grant.condition, query.context);
        }).map(function (grant) {
            return utils.toStringArray(grant.resource);
        }).reduce(Notation.Glob.union, []);
    },
    getUnionActionsOfRoles: function (grants, query) {
        query.skipConditions = query.skipConditions || !query.context;
        return utils.getUnionGrantsOfRoles(grants, query)
            .filter(function (grant) {
            return (query.skipConditions || condtions_1.conditionEvaluator(grant.condition, query.context)) &&
                MicroMatch.some(query.resource, grant.resource);
        }).map(function (grant) {
            return utils.toStringArray(grant.action);
        }).reduce(Notation.Glob.union, []);
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
    getUnionAttrsOfRoles: function (grants, query) {
        return utils.getUnionGrantsOfRoles(grants, query).filter(function (grant) {
            return MicroMatch.some(query.resource, grant.resource)
                && MicroMatch.some(query.action, grant.action)
                && (query.skipConditions || condtions_1.conditionEvaluator(grant.condition, query.context));
        }).map(function (grant) {
            return grant.attributes.slice();
        }).reduce(Notation.Glob.union, []);
    },
    areGrantsAllowing: function (grants, query) {
        if (!grants) {
            return false;
        }
        return grants.some(function (grant) {
            return MicroMatch.some(query.resource, grant.resource)
                && MicroMatch.some(query.action, grant.action)
                && (query.skipConditions || condtions_1.conditionEvaluator(grant.condition, query.context));
        });
    },
    areExtendingRolesAllowing: function (roleExtensionObject, allowingRoles, query) {
        if (!roleExtensionObject) {
            return false;
        }
        return Object.keys(roleExtensionObject).some(function (role) {
            return allowingRoles[role] &&
                (query.skipConditions || condtions_1.conditionEvaluator(roleExtensionObject[role].condition, query.context));
        });
    },
    getAllowingRoles: function (grants, query) {
        if (!grants) {
            throw new core_1.AccessControlError('Grants are not set.');
        }
        var roles = Object.keys(grants);
        var allowingRoles = {};
        roles.sort(function (role1, role2) {
            return grants[role1].score - grants[role2].score;
        }).reduce(function (allowingRoles, role) {
            allowingRoles[role] = utils.areGrantsAllowing(grants[role].grants, query) ||
                utils.areExtendingRolesAllowing(grants[role].$extend, allowingRoles, query);
            return allowingRoles;
        }, allowingRoles);
        return Object.keys(allowingRoles).filter(function (role) {
            return allowingRoles[role];
        });
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
        var allExtendingRoles = utils.getFlatRoles(grants, arrExtRoles, null, true);
        var extensionScore = allExtendingRoles.reduce(function (total, role) {
            return total + grants[role].score;
        }, 0);
        roles.forEach(function (role) {
            if (allExtendingRoles.indexOf(role) >= 0) {
                throw new core_1.AccessControlError("Attempted to extend role \"" + role + "\" by itself.");
            }
            grants[role] = grants[role] || { score: 1 };
            grants[role].score += extensionScore;
            grants[role].$extend = grants[role].$extend || {};
            arrExtRoles.forEach(function (extRole) {
                grants[role].$extend[extRole] = grants[role].$extend[extRole] || {};
                grants[role].$extend[extRole].condition = condition;
            });
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

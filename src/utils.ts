// dep modules
import * as Notation from 'notation';
import * as Matcher from 'matcher';
// own modules
import { IAccessInfo, IQueryInfo, AccessControlError, ICondition } from './core';
import { conditionEvaluator } from './conditions';

const utils = {
    anyMatch(strings: string | string[], patterns: string | string[]) {
        const stringArray = utils.toStringArray(strings);
        const patternArray = utils.toStringArray(patterns);
        return Matcher(stringArray, patternArray).length !== 0;
    },
    clone(o: any): any {
        return JSON.parse(JSON.stringify(o));
    },

    type(o: any): string {
        return Object.prototype.toString.call(o).match(/\s(\w+)/i)[1].toLowerCase();
    },

    hasDefined(o: any, propName: string): boolean {
        return o.hasOwnProperty(propName) && o[propName] !== undefined;
    },

    toStringArray(value: any): string[] {
        if (Array.isArray(value)) return value.slice();
        if (typeof value === 'string') return value.trim().split(/\s*[;,]\s*/);
        // throw new Error('Cannot convert value to array!');
        return null;
    },

    toArray(value: any): any[] {
        if (Array.isArray(value)) return value.slice();
        return [value];
    },

    isFilledStringArray(arr: any[]): boolean {
        if (!arr || !Array.isArray(arr)) return false;
        for (let s of arr) {
            if (typeof s !== 'string' || s.trim() === '') return false;
        }
        return true;
    },

    isStringOrArray(value: any): boolean {
        return typeof value === 'string' || utils.isFilledStringArray(value);
    },

    isEmptyArray(value: any): boolean {
        return Array.isArray(value) && value.length === 0;
    },

    uniqConcat(arrA: string[], arrB: string[]): string[] {
        let arr: string[] = arrA.slice();
        arrB.forEach((b: string) => {
            if (arr.indexOf(b) < 0) arr.push(b);
        });
        return arr;
    },

    subtractArray(arrA: string[], arrB: string[]): string[] {
        return arrA.slice().filter(a => arrB.indexOf(a) === -1);
    },

    eachKey(o: any, callback: (key: string, index?: number) => void) {
        return Object.keys(o).forEach(callback);
    },

    /**
     *  Gets roles and extended roles in a flat array.
     */
    getFlatRoles(grants: any, roles: string | string[], context?: any, skipConditions?: boolean): string[] {
        roles = utils.toStringArray(roles);
        if (!roles) throw new AccessControlError(`Invalid role(s): ${JSON.stringify(roles)}`);
        let arr: string[] = roles.slice();
        roles.forEach((roleName: string) => {
            let roleItem: any = grants[roleName];
            if (!roleItem) throw new AccessControlError(`Role not found: "${roleName}"`);
            if (roleItem.$extend) {
                const rolesMetCondition = Object.keys(roleItem.$extend).filter((role) => {
                    return skipConditions || conditionEvaluator(roleItem.$extend[role].condition, context);
                });
                arr = utils.uniqConcat(arr, utils.getFlatRoles(grants, rolesMetCondition, context, skipConditions));
            }
        });
        return arr;
    },

    normalizeGrantsObject(grants: any): any {
        const grantsCopy = utils.clone(grants);
        for (let role in grantsCopy) {
            if (!grantsCopy[role].grants) {
                continue;
            }
            grantsCopy[role].grants.forEach((grant) => {
                grant.attributes = grant.attributes || ['*'];
            });
            grantsCopy[role].score = grantsCopy[role].score || 1;
        }
        return grantsCopy;
    },

    normalizeQueryInfo(query: IQueryInfo): IQueryInfo {
        // clone the object
        query = Object.assign({}, query);
        // validate and normalize role(s)
        query.role = utils.toStringArray(query.role);
        if (!utils.isFilledStringArray(query.role)) {
            throw new AccessControlError(`Invalid role(s): ${JSON.stringify(query.role)}`);
        }

        // validate resource
        if (query.resource) {
            if (typeof query.resource !== 'string' || query.resource.trim() === '') {
                throw new AccessControlError(`Invalid resource: "${query.resource}"`);
            }
            query.resource = query.resource.trim();
        }

        // validate action
        if (query.action) {
            if (typeof query.action !== 'string' || query.action.trim() === '') {
                throw new AccessControlError(`Invalid action: ${query.action}`);
            }
        }

        return query;
    },

    normalizeAccessInfo(access: IAccessInfo): IAccessInfo {
        // clone the object
        access = Object.assign({}, access);
        // validate and normalize role(s)
        access.role = utils.toStringArray(access.role);
        if (!utils.isFilledStringArray(access.role)) {
            throw new AccessControlError(`Invalid role(s): ${JSON.stringify(access.role)}`);
        }

        // validate and normalize resource
        access.resource = utils.toStringArray(access.resource);
        if (!utils.isFilledStringArray(access.resource)) {
            throw new AccessControlError(`Invalid resource(s): ${JSON.stringify(access.resource)}`);
        }

        // validate and normalize resource
        access.action = utils.toStringArray(access.action);
        if (!utils.isFilledStringArray(access.action)) {
            throw new AccessControlError(`Invalid resource(s): ${JSON.stringify(access.action)}`);
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
    resetAttributes(access: IAccessInfo): IAccessInfo {
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
    isInfoFulfilled(info: IAccessInfo | IQueryInfo): boolean {
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
    commitToGrants(grants: any, access: IAccessInfo) {
        access = utils.normalizeAccessInfo(access);
        (access.role as Array<string>).forEach((role: string) => {
            grants[role] = grants[role] || { score: 1 };
            grants[role].grants = grants[role].grants || []
            grants[role].grants.push({
                resource: access.resource,
                action: access.action,
                attributes: access.attributes,
                condition: access.condition
            });
        });
    },

    getUnionGrantsOfRoles(grants: any, query: IQueryInfo): any[] {
        if (!grants) {
            throw new AccessControlError('Grants are not set.');
        }

        // throws if has any invalid property value
        query = utils.normalizeQueryInfo(query);

        // get roles and extended roles in a flat array
        const roles: string[] = utils.getFlatRoles(grants, query.role, query.context, query.skipConditions);
        // iterate through roles and add permission attributes (array) of
        // each role to attrsList (array).
        return roles.filter((role) => {
            return grants[role] && grants[role].grants;
        }).map((role) => {
            return grants[role].grants;
        }).reduce((allGrants, roleGrants) => {
            return allGrants.concat(roleGrants);
        }, []).filter((grant) => {
            return query.skipConditions || conditionEvaluator(grant.condition, query.context);
        });
    },

    getUnionResourcesOfRoles(grants: any, query: IQueryInfo): string[] {
        query.skipConditions = query.skipConditions || !query.context;
        return utils.getUnionGrantsOfRoles(grants, query)
            .map((grant) => {
                return utils.toStringArray(grant.resource);
            }).reduce(Notation.Glob.union, []);
    },

    getUnionActionsOfRoles(grants: any, query: IQueryInfo): string[] {
        query.skipConditions = query.skipConditions || !query.context;
        return utils.getUnionGrantsOfRoles(grants, query)
            .filter((grant) => {
                return utils.anyMatch(query.resource, grant.resource)
            }).map((grant) => {
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
    getUnionAttrsOfRoles(grants: any, query: IQueryInfo): string[] {
        return utils.getUnionGrantsOfRoles(grants, query).filter((grant) => {
            return utils.anyMatch(query.resource, grant.resource)
                && utils.anyMatch(query.action, grant.action);
        }).map((grant) => {
            return grant.attributes.slice();
        }).reduce(Notation.Glob.union, []);
    },

    areGrantsAllowing(grants: IAccessInfo[], query: IQueryInfo) {
        if (!grants) {
            return false;
        }
        return grants.some((grant) => {
            return utils.anyMatch(query.resource, grant.resource)
                && utils.anyMatch(query.action, grant.action)
                && (query.skipConditions || conditionEvaluator(grant.condition, query.context));
        });
    },

    areExtendingRolesAllowing(roleExtensionObject: any, allowingRoles: any, query: IQueryInfo) {
        if (!roleExtensionObject) {
            return false;
        }
        return Object.keys(roleExtensionObject).some((role) => {
            return allowingRoles[role] &&
                (query.skipConditions || conditionEvaluator(roleExtensionObject[role].condition, query.context));
        });
    },

    getAllowingRoles(grants: any, query: IQueryInfo) {
        if (!grants) {
            throw new AccessControlError('Grants are not set.');
        }
        const roles = Object.keys(grants);
        const allowingRoles = {};
        roles.sort((role1, role2) => {
            return grants[role1].score - grants[role2].score
        }).reduce((allowingRoles, role) => {
            allowingRoles[role] = utils.areGrantsAllowing(grants[role].grants, query) ||
                utils.areExtendingRolesAllowing(grants[role].$extend, allowingRoles, query);
            return allowingRoles;
        }, allowingRoles);

        return Object.keys(allowingRoles).filter((role) => {
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
    getNonExistentRoles(grants: any, roles: string[]) {
        let non: string[] = [];
        for (let role of roles) {
            if (!grants.hasOwnProperty(role)) non.push(role);
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
    extendRole(grants: any, roles: string | string[], extenderRoles: string | string[], condition?: ICondition) {
        let arrExtRoles: string[] = utils.toStringArray(extenderRoles);
        if (!arrExtRoles) throw new AccessControlError(`Invalid extender role(s): ${JSON.stringify(extenderRoles)}`);
        let nonExistentExtRoles: string[] = utils.getNonExistentRoles(grants, arrExtRoles);
        if (nonExistentExtRoles.length > 0) {
            throw new AccessControlError(`Cannot extend with non-existent role(s): "${nonExistentExtRoles.join(', ')}"`);
        }
        roles = utils.toStringArray(roles);
        if (!roles) throw new AccessControlError(`Invalid role(s): ${JSON.stringify(roles)}`);
        const allExtendingRoles = utils.getFlatRoles(grants, arrExtRoles, null, true);
        const extensionScore = allExtendingRoles.reduce((total, role) => {
            return total + grants[role].score;
        }, 0)
        roles.forEach((role: string) => {
            if (allExtendingRoles.indexOf(role) >= 0) {
                throw new AccessControlError(`Attempted to extend role "${role}" by itself.`);
            }
            grants[role] = grants[role] || { score: 1 };
            grants[role].score += extensionScore;
            grants[role].$extend = grants[role].$extend || {};
            arrExtRoles.forEach((extRole) => {
                grants[role].$extend[extRole] = grants[role].$extend[extRole] || {};
                grants[role].$extend[extRole].condition = condition
            });
        });
    },

    matchesAllElement(values: any, predicateFn: (elm) => boolean) {
        values = utils.toArray(values);
        return values.every(predicateFn);
    },

    matchesAnyElement(values: any, predicateFn: (elm) => boolean) {
        values = utils.toArray(values);
        return values.some(predicateFn);
    },

    filter(object: any, attributes: string[]): any {
        if (!Array.isArray(attributes) || attributes.length === 0) {
            return {};
        }
        let notation = new Notation(object);
        return notation.filter(attributes).value;
    },

    filterAll(arrOrObj: any, attributes: string[]): any {
        if (!Array.isArray(arrOrObj)) {
            return utils.filter(arrOrObj, attributes);
        }
        return arrOrObj.map(o => {
            return utils.filter(o, attributes);
        });
    }

};

export default utils;

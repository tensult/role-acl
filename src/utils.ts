// dep modules
import * as Notation from 'notation';
// own modules
import { IAccessInfo, IQueryInfo, AccessControlError, ICondition } from './core';
import { Conditions, conditionEvaluator } from './condtions';

const utils = {

    type(o: any): string {
        return Object.prototype.toString.call(o).match(/\s(\w+)/i)[1].toLowerCase();
    },

    hasDefined(o: any, propName: string): boolean {
        return o.hasOwnProperty(propName) && o[propName] !== undefined;
    },

    toStringArray(value: any): string[] {
        if (Array.isArray(value)) return value;
        if (typeof value === 'string') return value.trim().split(/\s*[;,]\s*/);
        // throw new Error('Cannot convert value to array!');
        return null;
    },

    toArray(value: any): any[] {
        if (Array.isArray(value)) return value;
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
        let arr: string[] = arrA.concat();
        arrB.forEach((b: string) => {
            if (arr.indexOf(b) < 0) arr.push(b);
        });
        return arr;
    },

    subtractArray(arrA: string[], arrB: string[]): string[] {
        return arrA.concat().filter(a => arrB.indexOf(a) === -1);
    },

    eachKey(o: any, callback: (key: string, index?: number) => void) {
        return Object.keys(o).forEach(callback);
    },

    /**
     *  Gets roles and extended roles in a flat array.
     */
    getFlatRoles(grants: any, roles: string | string[], context?: any): string[] {
        roles = utils.toStringArray(roles);
        if (!roles) throw new AccessControlError(`Invalid role(s): ${JSON.stringify(roles)}`);
        let arr: string[] = roles.concat();
        roles.forEach((roleName: string) => {
            let role: any = grants[roleName];
            if (!role) throw new AccessControlError(`Role not found: "${roleName}"`);
            if (Array.isArray(role.$extend)) {
                const rolesMetCondition = role.$extend.filter((roleCondition: any) => {
                    return conditionEvaluator(roleCondition.condition, context);
                }).map((roleCondition: any) => {
                    return roleCondition.role;
                })
                arr = utils.uniqConcat(arr, utils.getFlatRoles(grants, rolesMetCondition, context));
            }
        });
        return arr;
    },

    normalizeAction(info: IQueryInfo | IAccessInfo): IQueryInfo | IAccessInfo {
        // validate and normalize action
        if (typeof info.action !== 'string') {
            throw new AccessControlError(`Invalid action: ${info.action}`);
        }

        return info;
    },

    normalizeQueryInfo(query: IQueryInfo, all: boolean = false): IQueryInfo {
        // clone the object
        query = Object.assign({}, query);
        // validate and normalize role(s)
        query.role = utils.toStringArray(query.role);
        if (!utils.isFilledStringArray(query.role)) {
            throw new AccessControlError(`Invalid role(s): ${JSON.stringify(query.role)}`);
        }

        // validate resource
        if (typeof query.resource !== 'string' || query.resource.trim() === '') {
            throw new AccessControlError(`Invalid resource: "${query.resource}"`);
        }
        query.resource = query.resource.trim();

        // this part is not necessary if this is invoked from a comitter method
        // such as `createAny()`. So we'll check if we need to validate all
        // properties such as `action`.
        if (all) query = utils.normalizeAction(query) as IQueryInfo;

        return query;
    },

    normalizeAccessInfo(access: IAccessInfo, all: boolean = false): IAccessInfo {
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

        access.attributes = !access.attributes ? ['*'] : utils.toStringArray(access.attributes);

        // this part is not necessary if this is invoked from a comitter method
        // such as `createAny()`. So we'll check if we need to validate all
        // properties such as `action`.
        if (all) access = utils.normalizeAction(access) as IAccessInfo;

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
     *  @param {Boolean} normalizeAll
     *         Specifies whether to validate and normalize all properties of
     *         the inner `IAccessInfo` object, including `action`.
     *  @throws {Error} If `IAccessInfo` object fails validation.
     */
    commitToGrants(grants: any, access: IAccessInfo, normalizeAll: boolean = false) {
        access = utils.normalizeAccessInfo(access, normalizeAll);
        // console.log(access);
        // grant.role also accepts an array, so treat it like it.
        (access.role as Array<string>).forEach((role: string) => {
            if (!grants.hasOwnProperty(role)) grants[role] = {};
            let grantItem: any = grants[role];

            let action: string = access.action;
            (access.resource as Array<string>).forEach((res: string) => {
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
    getUnionConditionalAttrsOfRoles(grants: any, query: IQueryInfo): string[] {
        if (!grants) {
            throw new AccessControlError('Grants are not set.');
        }
        // throws if has any invalid property value
        query = utils.normalizeQueryInfo(query);

        let attrsList: Array<any> = [];

        // get roles and extended roles in a flat array
        let roles: string[] = utils.getFlatRoles(grants, query.role, query.context);
        // iterate through roles and add permission attributes (array) of
        // each role to attrsList (array).
        roles.forEach((role: string, index: number) => {
            let grantItem = grants[role];
            if (grantItem) {
                let resource = grantItem[query.resource];
                if (resource) {
                    const actionAttrs: Array<any> = resource[query.action];
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
        roles.forEach((role: string) => {
            if (arrExtRoles.indexOf(role) >= 0) {
                throw new AccessControlError(`Attempted to extend role "${role}" by itself.`);
            }
            grants[role] = grants[role] || {};
            grants[role].$extend = grants[role].$extend || [];
            grants[role].$extend = grants[role].$extend.concat(arrExtRoles.map((extRole) => {
                return {
                    role: extRole,
                    condition
                }
            }));
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

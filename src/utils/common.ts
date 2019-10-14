import * as Notation from 'notation';
import * as Matcher from 'matcher';
import { ArrayUtil } from './array';
import { ConditionUtil } from '../conditions';
import { AccessControlError, IQueryInfo, IAccessInfo, ICondition } from '../core';

export class CommonUtil {

    public static isStringOrArray(value: any): boolean {
        return typeof value === 'string' || ArrayUtil.isFilledStringArray(value);
    }

    public static eachKey(obj: any, callback: (key: string, index?: number) => void): void {
        return Object.keys(obj).forEach(callback);
    }

    public static anyMatch(strings: string | string[], patterns: string | string[]): boolean {
        const stringArray = ArrayUtil.toStringArray(strings);
        const patternArray = ArrayUtil.toStringArray(patterns);
        return Matcher(stringArray, patternArray).length !== 0;
    }

    public static allTrue(booleanVals: boolean[]) {
        return booleanVals.every((booleanVal) => {
            return booleanVal;
        });
    }

    public static allFalse(booleanVals: boolean[]) {
        return booleanVals.every((booleanVal) => {
            return !booleanVal;
        });
    }

    public static someTrue(booleanVals: boolean[]) {
        return booleanVals.some((booleanVal) => {
            return booleanVal;
        });
    }

    public static toExtendedJSON(o: any): string {
        return JSON.stringify(o, function (key, value) {
            if (typeof value === 'function') {
                return '/Function(' + value.toString() + ')/';
            }
            return value;
        });
    }

    public static fromExtendedJSON(json: string): any {
        return JSON.parse(json, function (key, value) {
            if (typeof value === 'string' &&
                value.startsWith('/Function(') &&
                value.endsWith(')/')) {
                value = value.substring(10, value.length - 2);
                return new Function('return ' + value)();
            }
            return value;
        });
    }

    public static clone(o: any): object {
        return CommonUtil.fromExtendedJSON(CommonUtil.toExtendedJSON(o));
    }

    public static type(o: any): string {
        return Object.prototype.toString.call(o).match(/\s(\w+)/i)[1].toLowerCase();
    }

    public static hasDefined(o: any, propName: string): boolean {
        return o.hasOwnProperty(propName) && o[propName] !== undefined;
    }

    /**
     *  Gets roles and extended roles in a flat array.
     */
    public static async getFlatRoles(grants: any, roles: string | string[], context?: any, skipConditions?: boolean): Promise<string[]> {
        roles = ArrayUtil.toStringArray(roles);
        if (!roles) throw new AccessControlError(`Invalid role(s): ${JSON.stringify(roles)}`);
        let arr: string[] = roles.slice();
        for (let roleName of roles) {
            let roleItem: any = grants[roleName];
            if (!roleItem) throw new AccessControlError(`Role not found: "${roleName}"`);
            if (roleItem.$extend) {
                let rolesMetCondition = [];
                if (skipConditions) {
                    rolesMetCondition = Object.keys(roleItem.$extend);
                } else {
                    for (let extendedRoleName of Object.keys(roleItem.$extend)) {
                        if (await ConditionUtil.evaluate(roleItem.$extend[extendedRoleName].condition,
                            context)) {
                            rolesMetCondition.push(extendedRoleName);
                        }
                    }
                }
                arr = ArrayUtil.uniqConcat(arr, await this.getFlatRoles(grants, rolesMetCondition, context, skipConditions));
            }
        }
        return arr;
    }

    public static isPromise(obj: any) {
        return obj && typeof obj.then === 'function';
    }

    public static normalizeGrantsObject(grants: any): any {
        const grantsCopy = this.clone(grants);
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
    }

    public static normalizeQueryInfo(query: IQueryInfo): IQueryInfo {
        // clone the object
        query = Object.assign({}, query);
        // validate and normalize role(s)
        query.role = ArrayUtil.toStringArray(query.role);
        if (!ArrayUtil.isFilledStringArray(query.role)) {
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
    }

    public static normalizeAccessInfo(access: IAccessInfo): IAccessInfo {
        // clone the object
        access = Object.assign({}, access);
        // validate and normalize role(s)
        access.role = ArrayUtil.toStringArray(access.role);
        if (!ArrayUtil.isFilledStringArray(access.role)) {
            throw new AccessControlError(`Invalid role(s): ${JSON.stringify(access.role)}`);
        }

        // validate and normalize resource
        access.resource = ArrayUtil.toStringArray(access.resource);
        if (!ArrayUtil.isFilledStringArray(access.resource)) {
            throw new AccessControlError(`Invalid resource(s): ${JSON.stringify(access.resource)}`);
        }

        // validate and normalize resource
        access.action = ArrayUtil.toStringArray(access.action);
        if (!ArrayUtil.isFilledStringArray(access.action)) {
            throw new AccessControlError(`Invalid resource(s): ${JSON.stringify(access.action)}`);
        }

        access.attributes = !access.attributes ? ['*'] : ArrayUtil.toStringArray(access.attributes);

        return access;
    }

    /**
     *  Used to re-set (prepare) the `attributes` of an `IAccessInfo` object
     *  when it's first initialized with e.g. `.grant()` or `.deny()` chain
     *  methods.
     *  @param {IAccessInfo} access
     *  @returns {IAccessInfo}
     */
    public static resetAttributes(access: IAccessInfo): IAccessInfo {
        if (!access.attributes || ArrayUtil.isEmptyArray(access.attributes)) {
            access.attributes = ['*'];
        }
        return access;
    }

    /**
     *  Checks whether the given access info can be committed to grants model.
     *  @param {IAccessInfo|IQueryInfo} info
     *  @returns {Boolean}
     */
    public static isInfoFulfilled(info: IAccessInfo | IQueryInfo): boolean {
        return this.hasDefined(info, 'role')
            && this.hasDefined(info, 'action')
            && this.hasDefined(info, 'resource');
    }

    /**
     *  Commits the given `IAccessInfo` object to the grants model.
     *  CAUTION: if attributes is omitted, it will default to `['*']` which
     *  means "all attributes allowed".
     *  @param {Any} grants
     *  @param {IAccessInfo} access
     *  @throws {Error} If `IAccessInfo` object fails validation.
     */
    public static commitToGrants(grants: any, access: IAccessInfo): void {
        access = this.normalizeAccessInfo(access);
        (access.role as Array<string>).forEach((role: string) => {
            grants[role] = grants[role] || { score: 1 };
            grants[role].grants = grants[role].grants || [];
            grants[role].grants.push({
                resource: access.resource,
                action: access.action,
                attributes: access.attributes,
                condition: access.condition
            });
        });
    }

    public static async getUnionGrantsOfRoles(grants: any, query: IQueryInfo): Promise<IAccessInfo[]> {
        if (!grants) {
            throw new AccessControlError('Grants are not set.');
        }

        // throws if has any invalid property value
        query = this.normalizeQueryInfo(query);

        // get roles and extended roles in a flat array
        const roles: string[] = await this.getFlatRoles(grants, query.role, query.context, query.skipConditions);

        // iterate through roles and add permission attributes (array) of
        // each role to attrsList (array).
        return roles.filter((role) => {
            return grants[role] && grants[role].grants;
        }).map((role) => {
            return grants[role].grants;
        }).reduce((allGrants, roleGrants) => {
            return allGrants.concat(roleGrants);
        }, []);
    }

    public static async getUnionResourcesOfRoles(grants: any, query: IQueryInfo): Promise<string[]> {
        query.skipConditions = query.skipConditions || !query.context;

        const matchingGrants = (await this.getUnionGrantsOfRoles(grants, query));

        return (await this.filterGrantsAllowing(matchingGrants, query))
            .map((grant) => {
                return ArrayUtil.toStringArray(grant.resource);
            }).reduce(Notation.Glob.union, []);
    }

    public static async getUnionActionsOfRoles(grants: any, query: IQueryInfo): Promise<string[]> {
        query.skipConditions = query.skipConditions || !query.context;

        const matchingGrants = (await this.getUnionGrantsOfRoles(grants, query))
            .filter((grant) => {
                return this.anyMatch(query.resource, grant.resource)
            });

        return (await this.filterGrantsAllowing(matchingGrants, query))
            .map((grant) => {
                return ArrayUtil.toStringArray(grant.action);
            }).reduce(Notation.Glob.union, []);
    }

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
    public static async getUnionAttrsOfRoles(grants: any, query: IQueryInfo): Promise<string[]> {
        const matchingGrants = (await this.getUnionGrantsOfRoles(grants, query))
            .filter((grant) => {
                return this.anyMatch(query.resource, grant.resource)
                    && this.anyMatch(query.action, grant.action);
            });

        return (await this.filterGrantsAllowing(matchingGrants, query))
            .map((grant) => {
                return ArrayUtil.toStringArray(grant.attributes);
            }).reduce(Notation.Glob.union, []);
    }

    public static async filterGrantsAllowing(grants: IAccessInfo[], query: IQueryInfo): Promise<IAccessInfo[]> {
        if (query.skipConditions) {
            return grants;
        } else {
            const matchingGrants = [];
            for (let grant of grants) {
                if (await ConditionUtil.evaluate(grant.condition, query.context)) {
                    matchingGrants.push(grant);
                }
            }
            return matchingGrants;
        }
    }

    public static async areGrantsAllowing(grants: IAccessInfo[], query: IQueryInfo): Promise<boolean> {
        if (!grants) {
            return false;
        }
        let result = false;
        for (let grant of grants) {
            result = result || (this.anyMatch(query.resource, grant.resource)
                && this.anyMatch(query.action, grant.action)
                && (query.skipConditions || await ConditionUtil.evaluate(grant.condition, query.context)))
        }
        return result;
    }

    public static async areExtendingRolesAllowing(roleExtensionObject: any, allowingRoles: any, query: IQueryInfo): Promise<boolean> {
        if (!roleExtensionObject) {
            return false;
        }
        let result = false;
        for (let roleName in roleExtensionObject) {
            result = result || (allowingRoles[roleName] && (query.skipConditions ||
                await ConditionUtil.evaluate(roleExtensionObject[roleName].condition, query.context)));
        }
        return result;
    }

    public static async getAllowingRoles(grants: any, query: IQueryInfo): Promise<string[]> {
        if (!grants) {
            throw new AccessControlError('Grants are not set.');
        }
        const allowingRoles = {};
        let sortedRoles = Object.keys(grants).sort((role1, role2) => {
            return grants[role1].score - grants[role2].score
        });
        for (let role of sortedRoles) {
            allowingRoles[role] = await this.areGrantsAllowing(grants[role].grants, query) ||
                await this.areExtendingRolesAllowing(grants[role].$extend, allowingRoles, query);
        }
        return Object.keys(allowingRoles).filter((role) => {
            return allowingRoles[role];
        });
    }

    /**
     *  Checks the given grants model and gets an array of non-existent roles
     *  from the given roles.
     *  @param {Any} grants - Grants model to be checked.
     *  @param {Array<string>} roles - Roles to be checked.
     *  @returns {Array<String>} - Array of non-existent roles. Empty array if
     *  all exist.
     */
    public static getNonExistentRoles(grants: any, roles: string[]): string[] {
        let non: string[] = [];
        for (let role of roles) {
            if (!grants.hasOwnProperty(role)) non.push(role);
        }
        return non;
    }

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
    public static async extendRole(grants: any, roles: string | string[], extenderRoles: string | string[], condition?: ICondition): Promise<void> {
        let arrExtRoles: string[] = ArrayUtil.toStringArray(extenderRoles);
        if (!arrExtRoles) throw new AccessControlError(`Invalid extender role(s): ${JSON.stringify(extenderRoles)}`);
        let nonExistentExtRoles: string[] = this.getNonExistentRoles(grants, arrExtRoles);
        if (nonExistentExtRoles.length > 0) {
            throw new AccessControlError(`Cannot extend with non-existent role(s): "${nonExistentExtRoles.join(', ')}"`);
        }
        roles = ArrayUtil.toStringArray(roles);
        if (!roles) throw new AccessControlError(`Invalid role(s): ${JSON.stringify(roles)}`);
        const allExtendingRoles = await this.getFlatRoles(grants, arrExtRoles, null, true);
        const extensionScore = allExtendingRoles.reduce((total, role) => {
            return total + grants[role].score;
        }, 0);
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
    }

    public static matchesAllElement(values: any, predicateFn: (elm) => boolean): boolean {
        values = ArrayUtil.toArray(values);
        return values.every(predicateFn);
    }

    public static matchesAnyElement(values: any, predicateFn: (elm) => boolean): boolean {
        values = ArrayUtil.toArray(values);
        return values.some(predicateFn);
    }

    public static filter(object: any, attributes: string[]): any {
        if (!Array.isArray(attributes) || attributes.length === 0) {
            return {};
        }
        let notation = new Notation(object);
        return notation.filter(attributes).value;
    }

    public static filterAll(arrOrObj: any, attributes: string[]): any {
        if (!Array.isArray(arrOrObj)) {
            return this.filter(arrOrObj, attributes);
        }
        return arrOrObj.map(o => {
            return this.filter(o, attributes);
        });
    }

}

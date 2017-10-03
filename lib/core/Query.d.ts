import { IQueryInfo, Permission } from '../core';
/**
 *  Represents the inner `Query` class that helps build an access information
 *  for querying and checking permissions, from the underlying grants model.
 *  You can get a first instance of this class by calling
 *  `AccessControl#can(<role>)` method.
 *  @class
 *  @inner
 *  @memberof AccessControl
 */
declare class Query {
    /**
     *  Inner `IQueryInfo` object.
     *  @protected
     *  @type {IQueryInfo}
     */
    protected _: IQueryInfo;
    /**
     *  Main grants object.
     *  @protected
     *  @type {Any}
     */
    protected _grants: any;
    /**
     *  Initializes a new instance of `Query`.
     *  @private
     *
     *  @param {Any} grants
     *         Underlying grants model against which the permissions will be
     *         queried and checked.
     *  @param {string|Array<String>|IQueryInfo} [role]
     *         Either a single or array of roles or an
     *         {@link ?api=ac#AccessControl~IQueryInfo|`IQueryInfo` arbitrary object}.
     */
    constructor(grants: any, role?: string | string[] | IQueryInfo);
    /**
     *  A chainer method that sets the role(s) for this `Query` instance.
     *  @param {String|Array<String>} roles
     *         A single or array of roles.
     *  @returns {Query}
     *           Self instance of `Query`.
     */
    role(role: string | string[]): Query;
    /**
     *  A chainer method that sets the resource for this `Query` instance.
     *  @param {String} resource
     *         Target resource for this `Query` instance.
     *  @returns {Query}
     *           Self instance of `Query`.
     */
    resource(resource: string): Query;
    /**
     *  Queries the underlying grant model and checks whether the current
     *  role(s) can execute "action" on any instance of "resource".
     *
     *  @param {String} [resource]
     *         Defines the target resource to be checked.
     *         This is only optional if the target resource is previously
     *         defined. If not defined and omitted, this will throw.
     *
     *  @throws {Error} If the access query instance to be committed has any
     *  invalid data.
     *
     *  @returns {Permission}
     *           An object that defines whether the permission is granted; and
     *           the resource attributes that the permission is granted for.
     */
    on(resource: string, skipConditions?: boolean): Permission;
    /**
     *  A chainer method that sets the context for this `Query` instance.
     *  @param {String} context
     *         Target context for this `Query` instance.
     *  @returns {Query}
     *           Self instance of `Query`.
     */
    context(context: any): Query;
    /**
     * A chainer method that sets the skipConditions for this `Query` instance.
     * @param {Boolean} value
     *          Indicates if conditions to skipped while querying
     * @returns {Query}
     *           Self instance of `Query`.
     */
    skipConditions(value: boolean): Query;
    /**
     *  Alias of `context`
     */
    with(context: any): Query;
    /**
     *  A chainer method that sets the action for this `Query` instance.
     *
     * @param {String} action
     *         Action that we are check if role has access or not
     */
    execute(action: string): Query;
    /**
     *  @private
     *  @param {String} action
     *  @param {String} [resource]
     *  @returns {Permission}
     */
    private _getPermission(action, resource?, skipConditions?);
}
export { Query };

"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
var core_1 = require("../core");
var utils_1 = require("../utils");
/**
 *  Represents the inner `Query` class that helps build an access information
 *  for querying and checking permissions, from the underlying grants model.
 *  You can get a first instance of this class by calling
 *  `AccessControl#can(<role>)` method.
 *  @class
 *  @inner
 *  @memberof AccessControl
 */
var Query = /** @class */ (function () {
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
    function Query(grants, role) {
        /**
         *  Inner `IQueryInfo` object.
         *  @protected
         *  @type {IQueryInfo}
         */
        this._ = {};
        this._grants = grants;
        // if this is a (permission) object, we directly build attributes from
        // grants.
        if (utils_1.default.type(role) === 'object') {
            this._ = role;
        }
        else {
            // if this is just role(s); a string or array; we start building
            // the grant object for this.
            this._.role = role;
        }
    }
    // -------------------------------
    //  PUBLIC METHODS
    // -------------------------------
    /**
     *  A chainer method that sets the role(s) for this `Query` instance.
     *  @param {String|Array<String>} roles
     *         A single or array of roles.
     *  @returns {Query}
     *           Self instance of `Query`.
     */
    Query.prototype.role = function (role) {
        this._.role = role;
        return this;
    };
    /**
     *  A chainer method that sets the resource for this `Query` instance.
     *  @param {String} resource
     *         Target resource for this `Query` instance.
     *  @returns {Query}
     *           Self instance of `Query`.
     */
    Query.prototype.resource = function (resource) {
        this._.resource = resource;
        return this;
    };
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
    Query.prototype.on = function (resource) {
        return this._getPermission(this._.action, resource);
    };
    /**
     *  A chainer method that sets the context for this `Query` instance.
     *  @param {String} context
     *         Target context for this `Query` instance.
     *  @returns {Query}
     *           Self instance of `Query`.
     */
    Query.prototype.context = function (context) {
        this._.context = context;
        return this;
    };
    /**
     *  Alias of `context`
     */
    Query.prototype.with = function (context) {
        return this.context(context);
    };
    /**
     *  A chainer method that sets the action for this `Query` instance.
     *
     * @param {String} action
     *         Action that we are check if role has access or not
     */
    Query.prototype.execute = function (action) {
        this._.action = action;
        return this;
    };
    // -------------------------------
    //  PRIVATE METHODS
    // -------------------------------
    /**
     *  @private
     *  @param {String} action
     *  @param {String} [resource]
     *  @returns {Permission}
     */
    Query.prototype._getPermission = function (action, resource) {
        this._.action = action;
        if (resource)
            this._.resource = resource;
        return new core_1.Permission(this._grants, this._);
    };
    return Query;
}());
exports.Query = Query;

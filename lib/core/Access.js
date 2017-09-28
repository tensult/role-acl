"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
var utils_1 = require("../utils");
/**
 *  Represents the inner `Access` class that helps build an access information
 *  to be granted or denied; and finally commits it to the underlying grants
 *  model. You can get a first instance of this class by calling
 *  `AccessControl#grant()` or `AccessControl#deny()` methods.
 *  @class
 *  @inner
 *  @memberof AccessControl
 */
var Access = /** @class */ (function () {
    /**
     *  Initializes a new instance of `Access`.
     *  @private
     *
     *  @param {Any} grants
     *         Main grants object.
     *  @param {String|Array<String>|IAccessInfo} roleOrInfo
     *         Either an `IAccessInfo` object, a single or an array of
     *         roles. If an object is passed and attributes
     *         properties are optional. CAUTION: if attributes is omitted,
     *         and access is not denied, it will default to `["*"]` which means
     *         "all attributes allowed".
     *  @param {Boolean} denied
     *         Specifies whether this `Access` is denied.
     */
    function Access(grants, roleOrInfo) {
        /**
         *  Inner `IAccessInfo` object.
         *  @protected
         *  @type {IAccessInfo}
         */
        this._ = {};
        this._grants = grants;
        if (typeof roleOrInfo === 'string' || Array.isArray(roleOrInfo)) {
            this.role(roleOrInfo);
        }
        else if (utils_1.default.type(roleOrInfo) === 'object') {
            // if an IAccessInfo instance is passed and it has 'action' defined, we
            // should directly commit it to grants.
            this._ = roleOrInfo;
        }
        if (utils_1.default.isInfoFulfilled(this._)) {
            utils_1.default.commitToGrants(grants, this._);
        }
    }
    // -------------------------------
    //  PUBLIC METHODS
    // -------------------------------
    /**
     *  A chainer method that sets the role(s) for this `Access` instance.
     *  @param {String|Array<String>} value
     *         A single or array of roles.
     *  @returns {Access}
     *           Self instance of `Access`.
     */
    Access.prototype.role = function (value) {
        this._.role = value;
        return this;
    };
    /**
     *  A chainer method that sets the resource for this `Access` instance.
     *  @param {String|Array<String>} value
     *         Target resource for this `Access` instance.
     *  @returns {Access}
     *           Self instance of `Access`.
     */
    Access.prototype.resource = function (value) {
        this._.resource = value;
        return this;
    };
    /**
     * Commits the grant
    *  @returns {Access}
     *           Self instance of `Access`.
     */
    Access.prototype.commit = function () {
        utils_1.default.commitToGrants(this._grants, this._);
        return this;
    };
    /**
     *  Sets the resource and commits the
     *  current access instance to the underlying grant model.
     *
     *  @param {String|Array<String>} [resource]
     *         Defines the target resource this access is granted or denied for.
     *         This is only optional if the resource is previously defined.
     *         If not defined and omitted, this will throw.
     *  @param {String|Array<String>} [attributes]
     *         Defines the resource attributes for which the access is granted
     *         for. If granted before via `.grant()`, this will default
     *         to `["*"]` (which means all attributes allowed.)
     *
     *  @throws {AccessControlError}
     *          If the access instance to be committed has any invalid
     *  data.
     *
     *  @returns {Access}
     *           Self instance of `Access` so that you can chain and define
     *           another access instance to be committed.
     */
    Access.prototype.on = function (resource, attributes) {
        return this._prepareAndCommit(this._.action, resource, attributes);
    };
    /**
     *  Sets the array of allowed attributes for this `Access` instance.
     *  @param {String|Array<String>} value
     *         Attributes to be set.
     *  @returns {Access}
     *           Self instance of `Access`.
     */
    Access.prototype.attributes = function (value) {
        this._.attributes = value;
        return this;
    };
    /**
     *  Sets condition for this `Access` instance.
     *  @param {Array<ICondition>|Array<Array<ICondition>>} value
     *         Conditions to be set.
     *  @returns {Access}
     *           Self instance of `Access`.
     */
    Access.prototype.condition = function (value) {
        this._.condition = value;
        return this;
    };
    /**
     *  Sets the roles to be extended for this `Access` instance.
     *  @param {String|Array<String>} roles
     *         A single or array of roles.
     *  @returns {Access}
     *           Self instance of `Access`.
     */
    Access.prototype.extend = function (roles) {
        utils_1.default.extendRole(this._grants, this._.role, roles);
        return this;
    };
    /**
     *  Shorthand to switch to a new `Access` instance with a different role
     *  within the method chain.
     *
     *  @param {String|Array<String>|IAccessInfo} [roleOrInfo]
     *         Either a single or an array of roles or an
     *         {@link ?api=ac#AccessControl~IAccessInfo|`IAccessInfo` object}.
     *
     *  @returns {Access}
     *           A new `Access` instance.
     *
     *  @example
     *  ac.grant('user').createOwn('video')
     *    .grant('admin').updateAny('video');
     */
    Access.prototype.grant = function (roleOrInfo) {
        return (new Access(this._grants, roleOrInfo)).attributes(['*']);
    };
    /**
     *  Sets the action.
     *
     *  @param {String} action
     *         Defines the action this access is granted for.
     *
     *  @returns {Access}
     *           Self instance of `Access` so that you can chain and define
     *           another access instance to be committed.
     */
    Access.prototype.execute = function (action) {
        this._.action = action;
        return this;
    };
    /**
     * Alias of `execute`
     */
    Access.prototype.action = function (action) {
        this._.action = action;
        return this;
    };
    /**
     *  Sets the condition for access.
     *
     *  @param {String} condition
     *         Defines the action this access is granted for.
     *
     *  @returns {Access}
     *           Self instance of `Access` so that you can chain and define
     *           another access instance to be committed.
     */
    Access.prototype.when = function (condtion) {
        this._.condition = condtion;
        return this;
    };
    // -------------------------------
    //  PRIVATE METHODS
    // -------------------------------
    /**
     *  @private
     *  @param {String} action     [description]
     *  @param {String|Array<String>} resource   [description]
     *  @param {String|Array<String>} attributes [description]
     *  @returns {Access}
     *           Self instance of `Access`.
     */
    Access.prototype._prepareAndCommit = function (action, resource, attributes) {
        this._.action = action;
        if (resource)
            this._.resource = resource;
        if (attributes)
            this._.attributes = attributes;
        utils_1.default.commitToGrants(this._grants, this._);
        // important: reset attributes for chained methods
        this._.attributes = undefined;
        return this;
    };
    return Access;
}());
exports.Access = Access;

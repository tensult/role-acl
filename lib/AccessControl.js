"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
var core_1 = require("./core");
var utils_1 = require("./utils");
/**
 *  @classdesc
 *  AccessControl class that implements RBAC (Role-Based Access Control) basics
 *  and ABAC (Attribute-Based Access Control) <i>resource</i> and <i>action</i>
 *  attributes.
 *
 *  Construct an `AccessControl` instance by either passing a grants object (or
 *  array fetched from database) or simple omit `grants` parameter if you are
 *  willing to build it programmatically.
 *
 *  <p><pre><code> var grants = {
 *      role1: {
 *          grants: [
 *              {
 *                  resource: 'resource1',
 *                  action: 'create'
 *                  attributes: ['*']
 *              },
 *              {
 *                  resource: 'resource1',
 *                  action: 'read'
 *                  attributes: ['*']
 *              },
 *              {
 *                  resource: 'resource2',
 *                  action: 'create'
 *                  attributes: ['*']
 *              }
 *          ]
 *      },
 *      role2: { ... }
 *  };
 *  var ac = new AccessControl(grants);</code></pre></p>
 *
 *  The `grants` object can also be an array, such as a flat list
 *  fetched from a database.
 *
 *  <p><pre><code> var flatList = [
 *      { role: "role1", resource: "resource1", action: "create", attributes: [ attrs ] },
 *      { role: "role1", resource: "resource1", action: "read", attributes: [ attrs ] },
 *      { role: "role2", ... },
 *      ...
 *  ];</code></pre></p>
 *
 *  We turn this list into a hashtable for better performance. We aggregate
 *  the list by roles first, resources second.
 *
 *  Below are equivalent:
 *  <p><pre><code> var grants = { role: "role1", resource: "resource1", action: "create", attributes: [ attrs ] }
 *  var same = { role: "role1", resource: "resource1", action: "create", attributes: [ attrs ] }</code></pre></p>
 *
 *  So we can also initialize with this flat list of grants:
 *  <p><pre><code> var ac = new AccessControl(flatList);
 *  console.log(ac.getGrants());</code></pre></p>
 *
 *  @author   Dilip Kola (dilip@tensult.com)
 *  @license  MIT
 *
 *  @class
 *  @global
 *
 */
var AccessControl = /** @class */ (function () {
    /**
     *  Initializes a new instance of `AccessControl` with the given grants.
     *  @ignore
     *
     *  @param {Object|Array} grants - A list containing the access grant
     *      definitions. See the structure of this object in the examples.
     */
    function AccessControl(grants) {
        if (grants === void 0) { grants = {}; }
        this.setGrants(grants);
    }
    // -------------------------------
    //  PUBLIC METHODS
    // -------------------------------
    /**
     *  Gets the internal grants object that stores all current grants.
     *
     *  @return {Object} - Hash-map of grants.
     */
    AccessControl.prototype.getGrants = function () {
        return this._grants;
    };
    /**
     *  Sets all access grants at once, from an object or array.
     *  Note that this will reset the object and remove all previous grants.
     *  @chainable
     *
     *  @param {Object|Array} grantsObject - A list containing the access grant
     *         definitions.
     *
     *  @returns {AccessControl} - `AccessControl` instance for chaining.
     */
    AccessControl.prototype.setGrants = function (grantsObject) {
        var _this = this;
        this._grants = {};
        var type = utils_1.default.type(grantsObject);
        if (type === 'object') {
            this._grants = utils_1.default.normalizeGrantsObject(grantsObject);
        }
        else if (type === 'array') {
            grantsObject.forEach(function (item) { return utils_1.default.commitToGrants(_this._grants, item); });
        }
        return this;
    };
    /**
     *  Resets the internal grants object and removes all previous grants.
     *  @chainable
     *
     *  @returns {AccessControl} - `AccessControl` instance for chaining.
     */
    AccessControl.prototype.reset = function () {
        this._grants = {};
        return this;
    };
    /**
     *  Extends the given role(s) with privileges of one or more other roles.
     *  @chainable
     *
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
     *
     *  @returns {AccessControl} - `AccessControl` instance for chaining.
     *
     *  @throws {Error}
     *          If a role is extended by itself or a non-existent role.
     */
    AccessControl.prototype.extendRole = function (roles, extenderRoles, condition) {
        utils_1.default.extendRole(this._grants, roles, extenderRoles, condition);
        return this;
    };
    /**
     *  Removes all the given role(s) and their granted permissions, at once.
     *  @chainable
     *
     *  @param {String|Array<String>} roles - An array of roles to be removed.
     *      Also accepts a string that can be used to remove a single role.
     *
     *  @returns {AccessControl} - `AccessControl` instance for chaining.
     */
    AccessControl.prototype.removeRoles = function (roles) {
        var _this = this;
        var rolesToRemove = utils_1.default.toStringArray(roles).sort();
        // Remove these roles from $extend list of each remaining role.
        this._each(function (role, roleItem) {
            if (roleItem.$extend) {
                // Adjust scores and remove
                rolesToRemove.forEach(function (role) {
                    if (roleItem.$extend[role]) {
                        roleItem.score -= _this._grants[role].score;
                        delete roleItem.$extend[role];
                    }
                });
            }
        });
        rolesToRemove.forEach(function (role) {
            delete _this._grants[role];
        });
        return this;
    };
    /**
     *  Gets all the unique roles that have at least one access information.
     *
     *  @returns {Array<String>}
     *
     *  @example
     *  ac.grant('admin, user').createAny('video').grant('user').readOwn('profile');
     *  console.log(ac.getRoles()); // ["admin", "user"]
     */
    AccessControl.prototype.getRoles = function () {
        return Object.keys(this._grants);
    };
    /**
     *  Checks whether any permissions are granted to the given role.
     *
     *  @param {String} role - Role to be checked.
     *
     *  @returns {Boolean}
     */
    AccessControl.prototype.hasRole = function (role) {
        return this._grants.hasOwnProperty(role);
    };
    /**
     * Get roles which allow this permission
     * @param {IQueryInfo} - permission query object we want to check
     *
     * @returns {String[]} - roles
     */
    AccessControl.prototype.allowingRoles = function (query) {
        return utils_1.default.getAllowingRoles(this._grants, query);
    };
    /**
     * Get allowedResources
    *  @param {String | String[]} role - Role to be checked.
     *
     *  @returns {String[]} - resources
     */
    AccessControl.prototype.allowedResources = function (role) {
        return utils_1.default.getUnionResourcesOfRoles(this._grants, role);
    };
    /**
     *  Gets an instance of `Query` object. This is used to check whether
     *  the defined access is allowed for the given role(s) and resource.
     *  This object provides chainable methods to define and query the access
     *  permissions to be checked.
     *  @name AccessControl#can
     *  @alias AccessControl#access
     *  @function
     *  @chainable
     *
     *  @param {String|Array|IQueryInfo} role - A single role (as a string),
     *      a list of roles (as an array) or an {@link ?api=ac#AccessControl~IQueryInfo|`IQueryInfo` object}
     *      that fully or partially defines the access to be checked.
     *
     *  @returns {Query} - The returned object provides chainable
     *      methods to define and query the access permissions to be checked.
     *      See {@link ?api=ac#AccessControl~Query|`Query` inner class}.
     *
     *  @example
     *  var ac = new AccessControl(grants);
     *
     *  ac.can('admin').createAny('profile');
     *  // equivalent to:
     *  ac.can().role('admin').createAny('profile');
     *  // equivalent to:
     *  ac.can().role('admin').resource('profile').createAny();
     *
     *  // To check for multiple roles:
     *  ac.can(['admin', 'user']).createOwn('profile');
     *  // Note: when multiple roles checked, acquired attributes are unioned (merged).
     */
    AccessControl.prototype.can = function (role) {
        return new core_1.Query(this._grants, role);
    };
    /**
     *  Alias of `can()`.
     *  @private
     */
    AccessControl.prototype.access = function (role) {
        return this.can(role);
    };
    /**
     *  Gets an instance of `Permission` object that checks and defines
     *  the granted access permissions for the target resource and role.
     *  Normally you would use `AccessControl#can()` method to check for
     *  permissions but this is useful if you need to check at once by passing
     *  a `IQueryInfo` object; instead of chaining methods
     *  (as in `.can(<role>).<action>(<resource>)`).
     *
     *  @param {IQueryInfo} queryInfo
     *         A fulfilled {@link ?api=ac#AccessControl~IQueryInfo|`IQueryInfo` object}.
     *
     *  @returns {Permission} - An object that provides properties
     *  and methods that defines the granted access permissions. See
     *  {@link ?api=ac#AccessControl~Permission|`Permission` inner class}.
     *
     *  @example
     *  var ac = new AccessControl(grants);
     *  var permission = ac.permission({
     *      role: "user",
     *      action: "update,
     *      resource: "profile"
     *  });
     *  permission.granted; // Boolean
     *  permission.attributes; // Array e.g. [ 'username', 'password', 'company.*']
     *  permission.filter(object); // { username, password, company: { name, address, ... } }
     */
    AccessControl.prototype.permission = function (queryInfo) {
        return new core_1.Permission(this._grants, queryInfo);
    };
    /**
     *  Gets an instance of `Grant` (inner) object. This is used to grant access
     *  to specified resource(s) for the given role(s).
     *  @name AccessControl#grant
     *  @alias AccessControl#allow
     *  @function
     *  @chainable
     *
     *  @param {String|Array<String>|IAccessInfo} role
     *         A single role (as a string), a list of roles (as an array) or an
     *         {@link ?api=ac#AccessControl~IAccessInfo|`IAccessInfo` object}
     *         that fully or partially defines the access to be granted.
     *
     *  @return {Access}
     *          The returned object provides chainable properties to build and
     *          define the access to be granted. See the examples for details.
     *          See {@link ?api=ac#AccessControl~Access|`Access` inner class}.
     *
     *  @example
     *  var ac = new AccessControl(),
     *      attributes = ['*'];
     *
     *  ac.grant('admin').createAny('profile', attributes);
     *  // equivalent to:
     *  ac.grant().role('admin').createAny('profile', attributes);
     *  // equivalent to:
     *  ac.grant().role('admin').resource('profile').createAny(null, attributes);
     *  // equivalent to:
     *  ac.grant({
     *      role: 'admin',
     *      resource: 'profile',
     *  }).createAny(null, attributes);
     *  // equivalent to:
     *  ac.grant({
     *      role: 'admin',
     *      resource: 'profile',
     *      action: 'create:any',
     *      attributes: attributes
     *  });
     *  // equivalent to:
     *  ac.grant({
     *      role: 'admin',
     *      resource: 'profile',
     *      action: 'create',
     *      attributes: attributes
     *  });
     *
     *  // To grant same resource and attributes for multiple roles:
     *  ac.grant(['admin', 'user']).createOwn('profile', attributes);
     *
     *  // Note: when attributes is omitted, it will default to `['*']`
     *  // which means all attributes (of the resource) are allowed.
     */
    AccessControl.prototype.grant = function (role) {
        return new core_1.Access(this._grants, role);
    };
    /**
     *  Alias of `grant()`.
     *  @private
     */
    AccessControl.prototype.allow = function (role) {
        return this.grant(role);
    };
    // -------------------------------
    //  PRIVATE METHODS
    // -------------------------------
    /**
     *  @private
     */
    AccessControl.prototype._each = function (callback) {
        var _this = this;
        utils_1.default.eachKey(this._grants, function (role) { return callback(role, _this._grants[role]); });
    };
    /**
     *  @private
     */
    AccessControl.prototype._eachRole = function (callback) {
        utils_1.default.eachKey(this._grants, function (role) { return callback(role); });
    };
    Object.defineProperty(AccessControl, "Error", {
        /**
         *  Documented separately in AccessControlError
         *  @private
         */
        get: function () {
            return core_1.AccessControlError;
        },
        enumerable: true,
        configurable: true
    });
    // -------------------------------
    //  PUBLIC STATIC METHODS
    // -------------------------------
    /**
     *  A utility method for deep cloning the given data object(s) while
     *  filtering its properties by the given attribute (glob) notations.
     *  Includes all matched properties and removes the rest.
     *
     *  Note that this should be used to manipulate data / arbitrary objects
     *  with enumerable properties. It will not deal with preserving the
     *  prototype-chain of the given object.
     *
     *  @param {Object|Array} data - A single or array of data objects
     *      to be filtered.
     *  @param {Array|String} attributes - The attribute glob notation(s)
     *      to be processed. You can use wildcard stars (*) and negate
     *      the notation by prepending a bang (!). A negated notation
     *      will be excluded. Order of the globs do not matter, they will
     *      be logically sorted. Loose globs will be processed first and
     *      verbose globs or normal notations will be processed last.
     *      e.g. `[ "car.model", "*", "!car.*" ]`
     *      will be sorted as:
     *      `[ "*", "!car.*", "car.model" ]`.
     *      Passing no parameters or passing an empty string (`""` or `[""]`)
     *      will empty the source object.
     *
     *  @returns {Object|Array} - Returns the filtered data object or array
     *      of data objects.
     *
     *  @example
     *  var assets = { notebook: "Mac", car: { brand: "Ford", model: "Mustang", year: 1970, color: "red" } };
     *
     *  var filtered = AccessControl.filter(assets, [ "*", "!car.*", "car.model" ]);
     *  console.log(assets); // { notebook: "Mac", car: { model: "Mustang" } }
     *
     *  filtered = AccessControl.filter(assets, "*"); // or AccessControl.filter(assets, ["*"]);
     *  console.log(assets); // { notebook: "Mac", car: { model: "Mustang" } }
     *
     *  filtered = AccessControl.filter(assets); // or AccessControl.filter(assets, "");
     *  console.log(assets); // {}
     */
    AccessControl.filter = function (data, attributes) {
        return utils_1.default.filterAll(data, attributes);
    };
    /**
     *  Checks whether the given object is an instance of `AccessControl.Error`.
     *  @name AccessControl.isACError
     *  @alias AccessControl.isAccessControlError
     *  @function
     *
     *  @param {Any} object
     *         Object to be checked.
     *
     *  @returns {Boolean}
     */
    AccessControl.isACError = function (object) {
        return object instanceof core_1.AccessControlError;
    };
    /**
     *  Alias of `isACError`
     *  @private
     */
    AccessControl.isAccessControlError = function (object) {
        return AccessControl.isACError(object);
    };
    return AccessControl;
}());
exports.AccessControl = AccessControl;

"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
var index_1 = require("./index");
var core_1 = require("../core");
var utils_1 = require("../utils");
/**
 * Or condition
 *
 *  @author Dilip Kola <dilip@tensult.com>
 */
var OrCondition = /** @class */ (function () {
    function OrCondition() {
    }
    OrCondition.prototype.evaluate = function (args, context) {
        if (!args) {
            return true;
        }
        if (!context) {
            return false;
        }
        if (utils_1.default.type(args) !== 'array' && utils_1.default.type(args) !== 'object') {
            throw new core_1.AccessControlError('OrCondition expects type of args to be array or object');
        }
        var conditions = utils_1.default.toArray(args);
        return conditions.some(function (condition) {
            return index_1.conditionEvaluator(condition, context);
        });
    };
    return OrCondition;
}());
exports.OrCondition = OrCondition;

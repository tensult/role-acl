"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
var index_1 = require("./index");
var core_1 = require("../core");
var utils_1 = require("../utils");
/**
 * And condition
 *
 *  @author Dilip Kola <dilip@tensult.com>
 */
var AndCondition = /** @class */ (function () {
    function AndCondition() {
    }
    AndCondition.prototype.evaluate = function (args, context) {
        if (!args) {
            return true;
        }
        if (!context) {
            return false;
        }
        if (utils_1.default.type(args) !== 'array' && utils_1.default.type(args) !== 'object') {
            throw new core_1.AccessControlError('AndCondition expects type of args to be array or object');
        }
        var conditions = utils_1.default.toArray(args);
        return conditions.every(function (condition) {
            return index_1.conditionEvaluator(condition, context);
        });
    };
    return AndCondition;
}());
exports.AndCondition = AndCondition;

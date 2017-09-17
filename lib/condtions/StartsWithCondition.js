"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
var core_1 = require("../core");
var utils_1 = require("../utils");
var StartsWithCondition = /** @class */ (function () {
    function StartsWithCondition() {
    }
    StartsWithCondition.prototype.evaluate = function (args, context) {
        if (!args) {
            return true;
        }
        if (!context) {
            return false;
        }
        if (utils_1.default.type(args) !== 'object') {
            throw new core_1.AccessControlError('StartsWithCondition expects type of args to be object');
        }
        return Object.keys(args).every(function (key) {
            return utils_1.default.type(context[key]) !== 'string'
                && utils_1.default.matchesAnyElement(args[key], function (elm) {
                    return context[key].startsWith(elm);
                });
        });
    };
    return StartsWithCondition;
}());
exports.StartsWithCondition = StartsWithCondition;

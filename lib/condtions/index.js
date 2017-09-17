"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
var TrueCondition_1 = require("./TrueCondition");
var EqualsCondition_1 = require("./EqualsCondition");
var NotEqualsCondition_1 = require("./NotEqualsCondition");
var NotCondition_1 = require("./NotCondition");
var ListContainsCondition_1 = require("./ListContainsCondition");
var OrCondition_1 = require("./OrCondition");
var AndCondition_1 = require("./AndCondition");
var core_1 = require("../core");
var Conditions;
(function (Conditions) {
    Conditions.AND = new AndCondition_1.AndCondition();
    Conditions.TRUE = new TrueCondition_1.TrueCondition();
    Conditions.EQUALS = new EqualsCondition_1.EqualsCondition();
    Conditions.LIST_CONTAINS = new ListContainsCondition_1.ListContainsCondition();
    Conditions.NOT_EQUALS = new NotEqualsCondition_1.NotEqualsCondition();
    Conditions.NOT = new NotCondition_1.NotCondition();
    Conditions.OR = new OrCondition_1.OrCondition();
})(Conditions = exports.Conditions || (exports.Conditions = {}));
exports.conditionEvaluator = function (condition, context) {
    if (!condition) {
        return true;
    }
    if (!Conditions[condition.Fn]) {
        throw new core_1.AccessControlError("Condtion function:" + condition.Fn + " not found");
    }
    return Conditions[condition.Fn].evaluate(condition.args, context);
};

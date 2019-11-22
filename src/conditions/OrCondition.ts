import { CommonUtil } from './../utils/common';
import { IConditionFunction } from './IConditionFunction';
import { ConditionUtil } from './index';
import { AccessControlError } from '../core';
import { ArrayUtil } from '../utils/';

/**
 * Or condition
 *
 *  @author Dilip Kola <dilip@tensult.com>
 */
export class OrCondition implements IConditionFunction {

    evaluate(args?: any, context?: any): boolean | Promise<boolean> {
        if (!args) {
            return true;
        }

        if (!context) {
            return false;
        }

        if (CommonUtil.type(args) !== 'array' && CommonUtil.type(args) !== 'object') {
            throw new AccessControlError('OrCondition expects type of args to be array or object')
        }

        const conditions = ArrayUtil.toArray(args);
        const conditionEvaluations = conditions.map((condition) => {
            return ConditionUtil.evaluate(condition, context);
        });
        if (CommonUtil.containsPromises(conditionEvaluations)) {
            return Promise.all(conditionEvaluations).then(CommonUtil.someTrue);
        } else {
            return CommonUtil.someTrue(conditionEvaluations as boolean[]);
        }
    }
}



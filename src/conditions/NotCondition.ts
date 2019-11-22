import { CommonUtil } from './../utils/common';
import { IConditionFunction } from './IConditionFunction';
import { ConditionUtil } from './index';
import { AccessControlError, ICondition } from '../core';
import { ArrayUtil } from '../utils/';

/**
 * Not condition
 *
 *  @author Dilip Kola <dilip@tensult.com>
 */

export class NotCondition implements IConditionFunction {

    evaluate(args?: any, context?: any): boolean | Promise<boolean> {
        if (!args) {
            return true;
        }

        if (!context) {
            return false;
        }

        if (CommonUtil.type(args) !== 'array' && CommonUtil.type(args) !== 'object') {
            throw new AccessControlError('NotCondition expects type of args to be array or object')
        }

        const conditions = ArrayUtil.toArray(args);

        const conditionEvaluations = conditions.map((condition) => {
            return ConditionUtil.evaluate(condition, context);
        });
        if (CommonUtil.containsPromises(conditionEvaluations)) {
            return Promise.all(conditionEvaluations).then(CommonUtil.allFalse);
        } else {
            return CommonUtil.allFalse(conditionEvaluations as boolean[]);
        }
    }
}



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
            throw new AccessControlError('AndCondition expects type of args to be array or object')
        }

        return this.evaluateConditions(ArrayUtil.toArray(args), context);
    }

    private evaluateConditions(conditions: ICondition[], context?: any): boolean | Promise<boolean> {
        const conditionPromisables = conditions.map((condition) => {
            return ConditionUtil.evaluate(condition, context);
        });

        const anyConditionIsPromise = conditionPromisables.some((conditionPromisable) => {
            return CommonUtil.isPromise(conditionPromisable);
        });

        if (anyConditionIsPromise) {
            return Promise.all(conditionPromisables).then(CommonUtil.allFalse);
        } else {
            return CommonUtil.allFalse(conditionPromisables as boolean[]);
        }
    }
}



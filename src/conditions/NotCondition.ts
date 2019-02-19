import { CommonUtil } from './../utils/common';
import { IConditionFunction } from './IConditionFunction';
import { conditionEvaluator } from './index';
import { AccessControlError, ICondition } from '../core';
import utils from '../utils';
import { ArrayUtil } from '../utils/';

/**
 * Not condition
 *
 *  @author Dilip Kola <dilip@tensult.com>
 */

export class NotCondition implements IConditionFunction {

    evaluate(args?: any, context?: any) {
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

        return conditions.every((condition: ICondition) => {
            return !conditionEvaluator(condition, context);
        });
    }
}



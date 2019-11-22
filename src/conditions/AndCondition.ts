import { IConditionFunction } from './IConditionFunction';
import { ConditionUtil } from './index';
import { AccessControlError } from '../core';
import { ArrayUtil, CommonUtil } from '../utils/';

/**
 * And condition
 *
 *  @author Dilip Kola <dilip@tensult.com>
 */
export class AndCondition implements IConditionFunction {

     evaluate(args?: any, context?: any):boolean | Promise<boolean> {
        if (!args) {
            return true;
        }

        if (!context) {
            return false;
        }

        if (CommonUtil.type(args) !== 'array' && CommonUtil.type(args) !== 'object') {
            throw new AccessControlError('AndCondition expects type of args to be array or object')
        }

        const conditions = ArrayUtil.toArray(args);
        const conditionEvaluations = conditions.map((condition) => {
            return ConditionUtil.evaluate(condition, context);
        });
        if (CommonUtil.containsPromises(conditionEvaluations)) {
            return Promise.all(conditionEvaluations).then(CommonUtil.allTrue);
        } else {
            return CommonUtil.allTrue(conditionEvaluations as boolean[]);
        }
    }
}



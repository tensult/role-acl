import { IConditionFunction } from './IConditionFunction';
import { conditionEvaluator } from './index';
import { AccessControlError, ICondition } from '../core';
import utils from '../utils';

/**
 * Or condition
 *
 *  @author Dilip Kola <dilip@tensult.com>
 */
export class OrCondition implements IConditionFunction {

    evaluate(args?: any, context?: any) {
        if (!args) {
            return true;
        }

        if (!context) {
            return false;
        }

        if (utils.type(args) !== 'array' && utils.type(args) !== 'object') {
            throw new AccessControlError('OrCondition expects type of args to be array or object')
        }

        const conditions = utils.toArray(args);

        return conditions.some((condition) => {
            return conditionEvaluator(condition, context);
        });
    }
}



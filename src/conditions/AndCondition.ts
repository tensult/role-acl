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

    async evaluate(args?: any, context?: any) {
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

        let result = true;
        for (let condition of conditions) {
            result = result && await ConditionUtil.evaluate(condition, context);
        }
        return result;
    }
}



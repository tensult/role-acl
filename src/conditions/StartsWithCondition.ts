import { CommonUtil } from './../utils/common';
import { IConditionFunction } from './IConditionFunction';
import { AccessControlError } from '../core';

/**
 * Starts with condition
 *
 *  @author Dilip Kola <dilip@tensult.com>
 */
export class StartsWithCondition implements IConditionFunction {

    evaluate(args?: any, context?: any) {
        if (!args) {
            return true;
        }

        if (!context) {
            return false;
        }

        if (CommonUtil.type(args) !== 'object') {
            throw new AccessControlError('StartsWithCondition expects type of args to be object')
        }

        return Object.keys(args).every((key) => {
            return CommonUtil.type(context[key]) === 'string'
                && CommonUtil.matchesAnyElement(args[key],
                    (elm) => {
                        return context[key].startsWith(elm)
                    });
        });
    }
}



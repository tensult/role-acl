import { IConditionFunction } from './IConditionFunction';
import { AccessControlError } from '../core';
import utils from '../utils';

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

        if (utils.type(args) !== 'object') {
            throw new AccessControlError('StartsWithCondition expects type of args to be object')
        }

        return Object.keys(args).every((key) => {
            return utils.type(context[key]) === 'string'
                && utils.matchesAnyElement(args[key],
                    (elm) => {
                        return context[key].startsWith(elm)
                    });
        });
    }
}



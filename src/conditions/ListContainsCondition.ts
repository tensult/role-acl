import { IConditionFunction } from "./IConditionFunction";
import { AccessControlError } from '../core';
import utils from '../utils';
/**
 * List contains condition 
 * 
 *  @author Dilip Kola <dilip@tensult.com>
 */
export class ListContainsCondition implements IConditionFunction {

    evaluate(args?: any, context?: any) {
        if (!args) {
            return true;
        }

        if (!context) {
            return false;
        }

        if (utils.type(args) !== 'object') {
            throw new AccessControlError('EqualsCondition expects type of args to be object')
        }

        return Object.keys(args).every((key) => {
            return Array.isArray(context[key]) &&
                utils.matchesAnyElement(args[key], (elm) => { return context[key].includes(elm); })
        });
    }
}



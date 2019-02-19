import { CommonUtil } from './../utils/';
import { IConditionFunction } from './IConditionFunction';
import { AccessControlError } from '../core';

/**
 * Not equals condition
 *
 *  @author Dilip Kola <dilip@tensult.com>
 */
export class NotEqualsCondition implements IConditionFunction {

    evaluate(args?: any, context?: any) {
        if (!args) {
            return true;
        }
        if (!context) {
            return false;
        }
        if (CommonUtil.type(args) !== 'object') {
            throw new AccessControlError('EqualsCondition expects type of args to be object')
        }
        return Object.keys(args).every((key) => {
            return CommonUtil.matchesAllElement(args[key], (elm) => { return elm !== context[key] })
        });
    }
}



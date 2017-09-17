import { IConditionFunction } from "./IConditionFunction";
import {AccessControlError} from '../core';
import utils from '../utils';

export class NotEqualsCondition implements IConditionFunction {

    evaluate(args?: any, context?: any) {
        if (!args) {
            return true;
        }
        if (!context) {
            return false;
        }
        if(utils.type(args) !== 'object') {
            throw new AccessControlError('EqualsCondition expects type of args to be object') 
        }
        return Object.keys(args).every((key) => {
            return utils.matchesAllElement(args[key], (elm) => { return elm !== context[key] })
        });
    }
}



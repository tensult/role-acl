import { IConditionFunction } from "./IConditionFunction";
import { conditionEvaluator } from "./index";
import {AccessControlError, ICondition} from '../core';
import utils from '../utils';

export class AndCondition implements IConditionFunction {

    evaluate(args?: any, context?: any) {
        if (!args) {
            return true;
        }

        if (!context) {
            return false;
        }

        if(utils.type(args) !== 'array' && utils.type(args) !== 'object') {
            throw new AccessControlError('AndCondition expects type of args to be array or object') 
        }

        const conditions = utils.toArray(args);

        return conditions.every((condition) => {
            return conditionEvaluator(condition, context);
        });
        
    }
}



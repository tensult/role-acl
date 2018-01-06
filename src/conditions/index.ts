import { TrueCondition } from './TrueCondition';
import { EqualsCondition } from './EqualsCondition';
import { NotEqualsCondition } from './NotEqualsCondition';
import { NotCondition } from './NotCondition';
import { ListContainsCondition } from './ListContainsCondition';
import { IConditionFunction } from './IConditionFunction';
import { OrCondition } from "./OrCondition";
import { AndCondition } from "./AndCondition";
import { StartsWithCondition } from "./StartsWithCondition";
import { AccessControlError, ICondition } from '../core';

export namespace Conditions {
    export const AND = new AndCondition();    
    export const TRUE = new TrueCondition();
    export const EQUALS = new EqualsCondition();
    export const LIST_CONTAINS = new ListContainsCondition();
    export const NOT_EQUALS = new NotEqualsCondition();
    export const NOT = new NotCondition();
    export const OR = new OrCondition();
    export const STARTS_WITH = new StartsWithCondition();        
}

export const conditionEvaluator = (condition: ICondition, context): boolean => {
    if(!condition) {
        return true;
    }

    if(!Conditions[condition.Fn]) {
        throw new AccessControlError(`Condtion function:${condition.Fn} not found`)
    }
    return (Conditions[condition.Fn] as IConditionFunction).evaluate(condition.args, context);
}
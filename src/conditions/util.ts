import { JSONPath } from 'jsonpath-plus';

import { TrueCondition } from './TrueCondition';
import { EqualsCondition } from './EqualsCondition';
import { NotEqualsCondition } from './NotEqualsCondition';
import { NotCondition } from './NotCondition';
import { ListContainsCondition } from './ListContainsCondition';
import { OrCondition } from './OrCondition';
import { AndCondition } from './AndCondition';
import { StartsWithCondition } from './StartsWithCondition';
import { IConditionFunction } from './IConditionFunction';
import { AccessControlError, ICondition } from '../core';

export class ConditionUtil {
    public static readonly AND = new AndCondition();
    public static readonly TRUE = new TrueCondition();
    public static readonly EQUALS = new EqualsCondition();
    public static readonly LIST_CONTAINS = new ListContainsCondition();
    public static readonly NOT_EQUALS = new NotEqualsCondition();
    public static readonly NOT = new NotCondition();
    public static readonly OR = new OrCondition();
    public static readonly STARTS_WITH = new StartsWithCondition();

    public static evaluate(condition: ICondition, context): boolean {
        if (!condition) {
            return true;
        }

        if (typeof condition === 'function') {
            return condition(context);
        }

        if (typeof condition === 'object') {
            if (!ConditionUtil[condition.Fn]) {
                throw new AccessControlError(`Condition function:${condition.Fn} not found`)
            }
            return (ConditionUtil[condition.Fn] as IConditionFunction).evaluate(condition.args, context);
        }

        return false;
    }

    public static getValueByPath(context: any, valuePathOrValue: any) {
        // Check if the value is JSONPath
        if (typeof valuePathOrValue === 'string' && valuePathOrValue.startsWith('$.')) {
            return JSONPath({ path: valuePathOrValue, json: context, wrap: false });
        }
        return valuePathOrValue;
    }
}
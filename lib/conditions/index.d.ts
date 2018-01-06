import { TrueCondition } from './TrueCondition';
import { EqualsCondition } from './EqualsCondition';
import { NotEqualsCondition } from './NotEqualsCondition';
import { NotCondition } from './NotCondition';
import { ListContainsCondition } from './ListContainsCondition';
import { OrCondition } from "./OrCondition";
import { AndCondition } from "./AndCondition";
import { StartsWithCondition } from "./StartsWithCondition";
import { ICondition } from '../core';
export declare namespace Conditions {
    const AND: AndCondition;
    const TRUE: TrueCondition;
    const EQUALS: EqualsCondition;
    const LIST_CONTAINS: ListContainsCondition;
    const NOT_EQUALS: NotEqualsCondition;
    const NOT: NotCondition;
    const OR: OrCondition;
    const STARTS_WITH: StartsWithCondition;
}
export declare const conditionEvaluator: (condition: ICondition, context: any) => boolean;

import { IConditionFunction } from "./IConditionFunction";
/**
 * Not equals condition
 *
 *  @author Dilip Kola <dilip@tensult.com>
 */
export declare class NotEqualsCondition implements IConditionFunction {
    evaluate(args?: any, context?: any): boolean;
}

import { IConditionFunction } from "./IConditionFunction";
/**
 * Equals condition
 *
 *  @author Dilip Kola <dilip@tensult.com>
 */
export declare class EqualsCondition implements IConditionFunction {
    evaluate(args?: any, context?: any): boolean;
}

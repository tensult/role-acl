import { IConditionFunction } from "./IConditionFunction";
/**
 * Or condition
 *
 *  @author Dilip Kola <dilip@tensult.com>
 */
export declare class OrCondition implements IConditionFunction {
    evaluate(args?: any, context?: any): boolean;
}

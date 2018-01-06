import { IConditionFunction } from "./IConditionFunction";
/**
 * Not condition
 *
 *  @author Dilip Kola <dilip@tensult.com>
 */
export declare class NotCondition implements IConditionFunction {
    evaluate(args?: any, context?: any): boolean;
}

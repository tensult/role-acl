import { IConditionFunction } from "./IConditionFunction";
/**
 * And condition
 *
 *  @author Dilip Kola <dilip@tensult.com>
 */
export declare class AndCondition implements IConditionFunction {
    evaluate(args?: any, context?: any): boolean;
}

/**
 *  Condition function interface
 *  @interface
 *
 *  @author Dilip Kola <dilip@tensult.com>
 */

export interface IConditionFunction {
    evaluate(args?: any, context?: any): boolean | Promise<boolean>;
}

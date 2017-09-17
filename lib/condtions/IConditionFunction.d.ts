export interface IConditionFunction {
    evaluate(args?: any, context?: any): boolean;
}

import { IConditionFunction } from "./IConditionFunction";

export class TrueCondition implements IConditionFunction {
    evaluate() {
        return true;
    }
}



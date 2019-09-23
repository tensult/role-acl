import { IConditionFunction } from './IConditionFunction';

/**
 * True condition
 *
 *  @author Dilip Kola <dilip@tensult.com>
 */
export class TrueCondition implements IConditionFunction {
    evaluate() {
        return true;
    }
}
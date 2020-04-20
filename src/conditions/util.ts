import { JSONPath } from "jsonpath-plus";

import { TrueCondition as TrueConditionFunction } from "./TrueCondition";
import { EqualsCondition as EqualsConditionFucntion } from "./EqualsCondition";
import { NotEqualsCondition as NotEqualsConditionFunction } from "./NotEqualsCondition";
import { NotCondition as NotConditionFunction } from "./NotCondition";
import { ListContainsCondition as ListContainsConditionFunction } from "./ListContainsCondition";
import { OrCondition as OrConditionFunction } from "./OrCondition";
import { AndCondition as AndConditionFunction } from "./AndCondition";
import { StartsWithCondition } from "./StartsWithCondition";
import { IConditionFunction } from "./IConditionFunction";
import {
  AccessControlError,
  ICondition,
  IDictionary,
  IFunctionCondition,
} from "../core";

export class ConditionUtil {
  public static readonly AND = new AndConditionFunction();
  public static readonly TRUE = new TrueConditionFunction();
  public static readonly EQUALS = new EqualsConditionFucntion();
  public static readonly LIST_CONTAINS = new ListContainsConditionFunction();
  public static readonly NOT_EQUALS = new NotEqualsConditionFunction();
  public static readonly NOT = new NotConditionFunction();
  public static readonly OR = new OrConditionFunction();
  public static readonly STARTS_WITH = new StartsWithCondition();
  private static _customConditionFunctions: IDictionary<
    IFunctionCondition
  > = {};

  public static registerCustomConditionFunction(
    functionName: string,
    fn: IFunctionCondition
  ) {
    if (!functionName) {
      throw new AccessControlError(
        `Condition function name:${functionName} is not valid`
      );
    }

    if (!functionName.startsWith("custom:")) {
      functionName = "custom:" + functionName;
    }
    if (ConditionUtil._customConditionFunctions[functionName]) {
      console.warn("Replacing existing function: ", functionName, "with:", fn);
    }
    ConditionUtil._customConditionFunctions[functionName] = fn;
  }

  public static getCustomConditionFunctions() {
    return ConditionUtil._customConditionFunctions;
  }

  public static setCustomConditionFunctions(
    customConditionFunctions: IDictionary<IFunctionCondition> = {}
  ) {
    for (let conditionFnName in customConditionFunctions) {
      ConditionUtil.registerCustomConditionFunction(
        conditionFnName,
        customConditionFunctions[conditionFnName]
      );
    }
  }

  public static evaluate(
    condition: ICondition,
    context: any
  ): boolean | Promise<boolean> {
    if (!condition) {
      return true;
    }

    if (typeof condition === "function") {
      return condition(context);
    }

    if (typeof condition === "string") {
      if (!ConditionUtil._customConditionFunctions[condition]) {
        throw new AccessControlError(
          `Condition function: ${condition} not found`
        );
      }
      return ConditionUtil._customConditionFunctions[condition](context);
    }

    if (typeof condition === "object") {
      if (!condition.Fn) {
        throw new AccessControlError(
          `Condition function:${condition.Fn} is not valid`
        );
      }

      if (ConditionUtil[condition.Fn]) {
          return (ConditionUtil[condition.Fn] as IConditionFunction).evaluate(condition.args, context);
      } else if(ConditionUtil._customConditionFunctions[condition.Fn]) {
          return ConditionUtil._customConditionFunctions[condition.Fn](context, condition.args);
      } else {
        throw new AccessControlError(
            `Condition function:${condition.Fn} is not found`
          );
      }
    }

    return false;
  }

  public static getValueByPath(context: any, valuePathOrValue: any) {
    // Check if the value is JSONPath
    if (
      valuePathOrValue &&
      typeof valuePathOrValue === "string" &&
      valuePathOrValue.startsWith("$.")
    ) {
      let jsonPathVal = JSONPath({
        path: valuePathOrValue,
        json: context,
        wrap: false,
      });
      if (Array.isArray(jsonPathVal)) {
        jsonPathVal = jsonPathVal.flat();
      }
      return jsonPathVal;
    }
    return valuePathOrValue;
  }
}

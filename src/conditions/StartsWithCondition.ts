import { CommonUtil } from "./../utils/";
import { IConditionFunction } from "./IConditionFunction";
import { AccessControlError } from "../core";
import { ConditionUtil } from "./util";

/**
 * Starts with condition
 *
 *  @author Dilip Kola <dilip@tensult.com>
 */
export class StartsWithCondition implements IConditionFunction {
  evaluate(args?: any, context?: any) {
    if (!args) {
      return true;
    }

    if (!context) {
      return false;
    }

    if (CommonUtil.type(args) !== "object") {
      throw new AccessControlError(
        "StartsWithCondition expects type of args to be object"
      );
    }

    return Object.keys(args).every((key) => {
      const keyValue = key.startsWith("$.")
        ? ConditionUtil.getValueByPath(context, key)
        : context[key];

      return (
        keyValue &&
        CommonUtil.type(keyValue) === "string" &&
        CommonUtil.matchesAnyElement(args[key], (elm) => {
          return keyValue.startsWith(
            ConditionUtil.getValueByPath(context, elm)
          );
        })
      );
    });
  }
}

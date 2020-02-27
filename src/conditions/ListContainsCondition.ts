import { CommonUtil } from './../utils/common';
import { IConditionFunction } from './IConditionFunction';
import { AccessControlError } from '../core';
import { ConditionUtil } from './util';

/**
 * List contains condition
 *
 *  @author Dilip Kola <dilip@tensult.com>
 */
export class ListContainsCondition implements IConditionFunction {

    evaluate(args?: any, context?: any) {
        if (!args) {
            return true;
        }

        if (!context) {
            return false;
        }

        if (CommonUtil.type(args) !== 'object') {
            throw new AccessControlError('ListContainsCondition expects type of args to be object')
        }

        return Object.keys(args).every((key) => {
          
          const keyValue = key.startsWith('$.') ?  ConditionUtil.getValueByPath(context, key) : context[key];

            return Array.isArray(keyValue) &&
                CommonUtil.matchesAnyElement(args[key], (elm) => {
                    return keyValue.includes(ConditionUtil.getValueByPath(context, elm));
                });
        });
    }
}



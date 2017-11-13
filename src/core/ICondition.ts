

import {IDictionary} from './IDictionary'
/**
 *  An interface that defines condition for an access grant.
 *  @interface
 * 
 *  @author Dilip Kola <dilip@tensult.com>
 */

interface ICondition {
    Fn: string;
    args: string | string[] | IDictionary<any> | ICondition | ICondition[];
}

export { ICondition };

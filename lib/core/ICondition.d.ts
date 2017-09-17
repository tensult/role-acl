import { IDictionary } from './IDictionary';
/**
 *  An interface that defines condition for an access grant.
 *  @interface
 */
interface ICondition {
    Fn: string;
    args: string | string[] | IDictionary<any> | ICondition | ICondition[];
}
export { ICondition };

export class ArrayUtil {

    public static toStringArray(value: any): string[] {
        if (Array.isArray(value)) {
            return value.slice();
        }
        if (typeof value === 'string') {
            return value.trim().split(/\s*[;,]\s*/);
        }
        return null;
    }

    public static toArray(value: any): any[] {
        if (Array.isArray(value)) {
            return value.slice();
        }
        return [value];
    }

    public static isFilledStringArray(arr: any[]): boolean {
        if (!arr || !Array.isArray(arr)) {
            return false;
        }
        for (let element of arr) {
            if (typeof element !== 'string' || element.trim() === '') {
                return false;
            }
        }
        return true;
    }

    public static isEmptyArray(value: any): boolean {
        return Array.isArray(value) && value.length === 0;
    }

    public static uniqConcat(arrA: string[], arrB: string[]): string[] {
        let arr: string[] = arrA.slice();
        arrB.forEach((element: string) => {
            if (arr.indexOf(element) < 0) {
                arr.push(element);
            }
        });
        return arr;
    }

    public static subtractArray(arrA: string[], arrB: string[]) {
        return arrA.slice().filter(element => arrB.indexOf(element) === -1);
    }

}
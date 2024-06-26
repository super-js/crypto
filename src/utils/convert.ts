import {ASCII_ZERO} from "./ascii";

export interface ILengthToAsciiCodesOptions {
    noOfCharacters?: number;
    convertLengthToHexString?: boolean
}

export function characterCodesToDecimal(characters: number[]): number {
    return parseInt(
        Buffer.from(characters).toString('hex'),
        16
    )
}

export function lengthToAsciiCodes(length: number, options?: ILengthToAsciiCodesOptions): number[] {

    const _noOfCharacters = options?.noOfCharacters || 2;
    const lengthString = (options?.convertLengthToHexString ? decimalToHexString(length) : length).toString() + "";
    const paddedString = lengthString.padStart(_noOfCharacters, "0");
    let asciiCodes = [];

    for(let i = 0; i < _noOfCharacters; i++) {
        asciiCodes[i] = paddedString.charCodeAt(i);
    }

    return asciiCodes;
}

export function lengthToAsciiDecimal(length: number, options?: ILengthToAsciiCodesOptions): number {
    const bufferLengthAsciiCodes = lengthToAsciiCodes(length, options);
    return characterCodesToDecimal(bufferLengthAsciiCodes);
}

export function decimalToHexString(decimalNumber: number): string {
    return decimalNumber.toString(16);
}

export function hexStringToDecimal(hexString: string): number {
    return parseInt(hexString, 16);
}

export function bufferToAscii(buffer: Buffer): string {
    return buffer.toString('ascii').toUpperCase();
}

export function bufferToHex(buffer: Buffer): string {
    return buffer.toString('hex').toUpperCase();
}
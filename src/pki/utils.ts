import {KJUR,KEYUTIL,RSAKey} from "jsrsasign";

export type TKeyTypeInput = 'pkcs8prv' | 'pkcs8pub';
export type TKeyTypeOutput = 'PKCS1PRV' | 'PKCS8PRV';

export class CryptoUtils {

    public static derToHex(derBuffer: Buffer): string {
        return derBuffer.toString('hex');
    }

    public static keyDerToKey(derBuffer: Buffer, keyType: TKeyTypeInput): RSAKey | KJUR.crypto.DSA | KJUR.crypto.ECDSA {
        return KEYUTIL.getKey(CryptoUtils.derToHex(derBuffer), null, keyType)
    }

    public static keyDerToPem(derBuffer: Buffer, keyType: TKeyTypeInput, outputFormat?: TKeyTypeOutput) {
        const key = CryptoUtils.keyDerToKey(derBuffer, keyType);
        return KEYUTIL.getPEM(key, outputFormat);
    }

    // // public static keyHexToPem(hex: string, isPrivate: boolean): string {
    // //     const key = KEYUTIL.getKey(hex, null, isPrivate ? 'pkcs8prv' : 'pkcs8pub')
    // //     return KEYUTIL.getPEM(key, isPrivate ? 'PKCS1PRV' : undefined);
    // // }
    //
    // // public static publicDerKeyToPem(derBuffer: Buffer): string {
    // //     return CryptoUtils.keyDerToPem(derBuffer, false);
    // // }
    // //
    // public static privateHexKeyToPem(privateKey: string): string {
    //     return KJUR.asn1.ASN1Util.getPEMStringFromHex(privateKey, 'PRIVATE KEY');
    // }

    public static publicHexKeyToPem(privateKey: string): string {
        return KJUR.asn1.ASN1Util.getPEMStringFromHex(privateKey, 'PUBLIC KEY');
    }
}
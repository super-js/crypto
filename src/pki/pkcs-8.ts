import {CryptoUtils} from "./utils";

export class CryptoPkcs8 {

    public static privateDerKeyToPem(derBuffer: Buffer): string {
        return CryptoUtils.keyDerToPem(derBuffer, 'pkcs8prv', 'PKCS8PRV');
    }

    public static publicDerKeyToPem(derBuffer: Buffer): string {
        return CryptoUtils.keyDerToPem(derBuffer, 'pkcs8pub');
    }


}
import {CryptoUtils} from "./utils";

export class CryptoPkcs1 {

    public static privateDerKeyToPem(derBuffer: Buffer): string {
        return CryptoUtils.keyDerToPem(derBuffer, 'pkcs8prv', 'PKCS1PRV');
    }

}
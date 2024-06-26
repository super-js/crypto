import {KJUR, KEYUTIL} from "jsrsasign";
import {CryptoUtils} from "./utils";
import {IGetX509ExtensionsOptions, IX509Subject, X509} from "./x-509";
import {CryptoPkcs8} from "./pkcs-8";


export enum SigningAlgorithm {
    MD5withRSA = 'MD5withRSA',
    SHA1withRSA = 'SHA1withRSA',
    SHA224withRSA = 'SHA224withRSA',
    SHA256withRSA = 'SHA256withRSA',
    SHA384withRSA = 'SHA384withRSA',
    SHA512withRSA = 'SHA512withRSA',
    SHA1withECDSA = 'SHA1withECDSA',
    SHA224withECDSA = 'SHA224withECDSA',
    SHA256withECDSA = 'SHA256withECDSA',
    SHA384withECDSA = 'SHA384withECDSA',
    SHA512withECDSA = 'SHA512withECDSA'
}

export interface ICreateSigningRequestOptions extends Omit<IGetX509ExtensionsOptions, 'subjectKeyIdentifierPem' | 'authorityKeyIdentifierPem'> {
    publicKeyDer: Buffer;
    privateKeyDer: Buffer;
    subject: IX509Subject;
    signingAlgorithm?: SigningAlgorithm;
}

export interface ISigningRequestInfo {
    subject: string;
    publicKeyPem: string;
    signingAlgorithm: SigningAlgorithm;
    signatureHex: string;
}

export class CryptoPkcs10 {
    public static createSigningRequest(options: ICreateSigningRequestOptions): KJUR.asn1.csr.CertificationRequest {

        const privateKeyPem = CryptoPkcs8.privateDerKeyToPem(options.privateKeyDer);
        const publicKeyPem = CryptoPkcs8.publicDerKeyToPem(options.publicKeyDer);

        const csr = new KJUR.asn1.csr.CertificationRequest({
            subject: {
                str: X509.subjectToString(options.subject)
            },
            sbjprvkey: privateKeyPem,
            sbjpubkey: publicKeyPem,
            sigalg: options.signingAlgorithm || SigningAlgorithm.SHA384withECDSA
        });

        csr.sign();

        return csr;
    }

    public static createSigningRequestAsPem(options: ICreateSigningRequestOptions): string {
        return CryptoPkcs10.createSigningRequest(options).getPEM();
    }

    public static getSigningRequestInfo(csr: string): ISigningRequestInfo {
        const csrObject = KJUR.asn1.csr.CSRUtil.getParam(csr);

        return {
            publicKeyPem: KEYUTIL.getPEM(KEYUTIL.getKey(csrObject.sbjpubkey)),
            signatureHex: csrObject.sighex,
            signingAlgorithm: csrObject.sigalg as SigningAlgorithm,
            subject: csrObject.subject.str
        };
    }

}
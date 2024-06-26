import {KJUR, X509 as X509_UTILS} from "jsrsasign";
import {CryptoPkcs10, ICreateSigningRequestOptions, ISigningRequestInfo, SigningAlgorithm} from "./pkcs-10";
import {CryptoUtils} from "./utils";
import moment from "moment";
import * as crypto from "crypto";
import {CryptoPkcs8} from "./pkcs-8";


export interface IGetX509ExtensionsOptions {
    isCertificateAuthority?: boolean;
    subjectKeyIdentifierPem?: string;
    authorityKeyIdentifierPem?: string;
}

export interface IX509Subject {
    commonName: string;
    countryName: string;
    state: string;
    localityName: string;
    organizationName: string;
    organizationUnit: string;
    emailAddress?: string
}

export interface ICertificateInfo extends ISigningRequestInfo {
    version: number;
}

export interface ICreateCertificateOptions extends ICreateSigningRequestOptions {
    expiresInMonths: number;
}

export interface ICreateCertificateFromCsrOptions extends Omit<ICreateCertificateOptions, 'publicKeyDer' | 'privateKeyDer' | 'subject'> {
    csrPem: string;
    caCertPem: string;
    caPrivateKeyDer: Buffer;
    expiresInMonths: number;
}

export interface IValidityDates {
    notbefore: string;
    notafter: string;
}

export class X509 {

    private static getValidityDates(expiresInMonths: number): IValidityDates {

        const validityDates = {
            notbefore: `${moment().subtract(1, 'day').format('YYYYMMDDHHmmSS')}Z`,
            notafter: `${moment().add(expiresInMonths, 'months').format('YYYYMMDDHHmmSS')}Z`,
        };

        return validityDates;
    }

    public static createSelfSignedCertificate(options: ICreateCertificateOptions): KJUR.asn1.x509.Certificate {

        const privateKeyPem = CryptoPkcs8.privateDerKeyToPem(options.privateKeyDer);
        const publicKeyPem = CryptoPkcs8.publicDerKeyToPem(options.publicKeyDer);
        const subject = X509.subjectToString(options.subject);

        return new KJUR.asn1.x509.Certificate({
            sbjpubkey: publicKeyPem,
            subject: {str: subject},
            serial: {hex: X509.generateSerialNumber()},
            ext: X509.getExtensions({
                ...options,
                subjectKeyIdentifierPem: publicKeyPem
            }),
            sigalg: options.signingAlgorithm || SigningAlgorithm.SHA384withECDSA,
            ...X509.getValidityDates(options.expiresInMonths),
            issuer: {str: subject},
            cakey: privateKeyPem
        });
    }

    public static createSelfSignedCertificateAsPem(options: ICreateCertificateOptions): string {
        return X509.createSelfSignedCertificate(options).getPEM();
    }

    public static createCertificateFromCsr(options: ICreateCertificateFromCsrOptions): KJUR.asn1.x509.Certificate {
        const {csrPem,caCertPem, expiresInMonths,caPrivateKeyDer} = options;

        const csrInfo = CryptoPkcs10.getSigningRequestInfo(csrPem);
        const privateKeyPem = CryptoPkcs8.privateDerKeyToPem(caPrivateKeyDer);
        const caCert = X509.getCertificateInfo(caCertPem);

        return new KJUR.asn1.x509.Certificate({
            sbjpubkey: csrInfo.publicKeyPem,
            subject: {str: csrInfo.subject},
            serial: {hex: X509.generateSerialNumber()},
            ext: X509.getExtensions({
                ...options,
                subjectKeyIdentifierPem: csrInfo.publicKeyPem,
                authorityKeyIdentifierPem: caCert.publicKeyPem
            }),
            sigalg: options.signingAlgorithm || csrInfo.signingAlgorithm,
            ...X509.getValidityDates(expiresInMonths),
            issuer: {str: caCert.subject},
            cakey: privateKeyPem
        });
    }

    public static createCertificateFromCsrAsPem(options: ICreateCertificateFromCsrOptions): string {
        return X509.createCertificateFromCsr(options).getPEM();
    }

    public static getCertificateInfo(cert: string): ICertificateInfo {
        const x509Utils = new X509_UTILS();

        x509Utils.readCertPEM(cert);

        return {
            subject: x509Utils.getSubjectString(),
            signingAlgorithm: x509Utils.getSignatureAlgorithmName() as SigningAlgorithm,
            signatureHex: x509Utils.getSignatureValueHex(),
            publicKeyPem: CryptoUtils.publicHexKeyToPem(x509Utils.getPublicKeyHex()),
            version: x509Utils.getVersion()
        };
    }


    public static getExtensions(options: IGetX509ExtensionsOptions): Array<{ extname: string, [x: string]: any }> {

        let extensions = [];

        let basicConstraints = {extname: 'basicConstraints'};
        let keyUsage = {extname: 'keyUsage'};

        if(options.isCertificateAuthority) {
            basicConstraints['cA'] = true;
            basicConstraints['pathLen'] = 2;
            keyUsage['names'] = ["digitalSignature", "cRLSign", "keyCertSign"];
        } else {
            basicConstraints['endEntity'] = true;
            keyUsage['names'] = ["digitalSignature"];
        }

        if(options.subjectKeyIdentifierPem) extensions.push({extname: 'subjectKeyIdentifier', kid: options.subjectKeyIdentifierPem});
        if(options.authorityKeyIdentifierPem) extensions.push({extname: 'authorityKeyIdentifier', kid: options.authorityKeyIdentifierPem});

        extensions.push(...[
            basicConstraints,
            keyUsage
        ])

        return extensions;
    }

    public static subjectToString(subject: IX509Subject): string {
        let subjectString = `/CN=${subject.commonName}/C=${subject.countryName}/O=${subject.organizationName}/OU=${subject.organizationUnit}/L=${subject.localityName}/ST=${subject.state}`;

        if(subject.emailAddress) subjectString += `/EMAIL=${subject.emailAddress}`;

        return subjectString;
    }

    public static generateSerialNumber(): string {
        return crypto.randomBytes(20).toString("hex");
    }

}
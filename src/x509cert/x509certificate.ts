import { pki, md } from "node-forge";
import { randomBytes } from "crypto";

export interface X509CertificateOptions {
    serialNumber: string | undefined;
    validFrom: Date | undefined;
    validTo: Date | undefined;
    commonName: string;
    uri: string;
    organizationName: string | undefined;
    country: string | undefined;
    state: string | undefined;
    locality: string | undefined;
}

export interface X509CertificateOutput {
    pemCert?: string;
    pemPublicKey?: string;
    pemPrivateKey?: string;
}

export interface X509CertificateRequestOutput extends X509CertificateOutput {
    pemCSR?: string;
}

export class X509Certificate {

    private static createCertificate(options: X509CertificateOptions, 
                                    signKey?: pki.PrivateKey, 
                                    publicKey?: pki.PublicKey,
                                    issuer?: pki.CertificateField[],
                                    subs?: pki.CertificateField[]): X509CertificateOutput {
        if (!options.commonName && !options.uri) {
            throw new Error('commonName and uri must be defined.');
        }
        let keyPair;
        const cert = pki.createCertificate();
        if (publicKey) {
            cert.publicKey = publicKey;
        } else {
            keyPair = pki.rsa.generateKeyPair(2048);
            cert.publicKey = keyPair.publicKey;
        }

        cert.serialNumber = options.serialNumber ? options.serialNumber : '01' + randomBytes(19).toString("hex"); // serialNumber requires non-negative
        cert.validity.notBefore = options.validFrom ? options.validFrom : new Date();
        cert.validity.notAfter = options.validTo;
        if (!cert.validity.notAfter) {
            cert.validity.notAfter = new Date();
            cert.validity.notAfter.setFullYear(cert.validity.notBefore.getFullYear() + 1);
        }

        const attrs = [];
        attrs.push({ name: 'commonName', value: options.commonName });
        if (options.country) attrs.push({ name: 'countryName', value: options.country });
        if (options.state) attrs.push({ shortName: 'ST', value: options.state });
        if (options.locality) attrs.push({ name: 'localityName', value: options.locality });
        if (options.organizationName) attrs.push({ name: 'organizationName', value: options.organizationName });
        if (subs) {
            for (const field of subs) {
                if (!attrs.find(attr => attr['name'] === field.name || attr['shortName'] === field.shortName))
                    attrs.push({name: field.name, value: field.value});
            }
        }
        cert.setSubject(attrs);
        cert.setIssuer(issuer ? issuer : attrs);

        const extensions = [{
            name: 'basicConstraints',
            cA: true
        }, {
            name: 'keyUsage',
            keyCertSign: true,
            digitalSignature: true,
            nonRepudiation: true,
            keyEncipherment: true,
            dataEncipherment: true
        }, {
            name: 'extKeyUsage',
            serverAuth: true,
            clientAuth: true,
            codeSigning: true,
            emailProtection: true,
            timeStamping: true
        }, {
            name: 'nsCertType',
            client: true,
            server: true,
            email: true,
            objsign: true,
            sslCA: true,
            emailCA: true,
            objCA: true
        }, {
            name: 'subjectAltName',
            altNames: [{
                type: 6,
                value: options.uri
            }]
        }];
        cert.setExtensions(extensions);

        cert.sign(signKey ? signKey : keyPair.privateKey, md.sha256.create());

        return {
            pemCert: pki.certificateToPem(cert),
            pemPublicKey: publicKey ? pki.publicKeyToPem(publicKey) : pki.publicKeyToPem(keyPair.publicKey),
            pemPrivateKey: publicKey ? null : pki.privateKeyToPem(keyPair.privateKey)
        };
    }

    public static createSelfSignedCert(options: X509CertificateOptions): X509CertificateOutput {
        return X509Certificate.createCertificate(options);
    }

    public static createIntermediateCert(pemRootCA: string, pemRootCAKey: string, options: X509CertificateOptions): X509CertificateOutput {
        // Root CA certificate and key
        const rootCAKey = pki.privateKeyFromPem(pemRootCAKey);
        const rootCACert = pki.certificateFromPem(pemRootCA);

        return X509Certificate.createCertificate(options, rootCAKey, null, rootCACert.subject.attributes);
    }

    public static createCertificateByCSR(pemRootCA: string, pemRootCAKey: string, pemCSR: string, options: X509CertificateOptions): X509CertificateOutput {
        // Certificate Signing Request
        const csr = pki.certificationRequestFromPem(pemCSR);

        if (!csr.verify) {
            throw new Error('Signature not verified.');
        }

        // Root CA certificate and key
        const rootCAKey = pki.privateKeyFromPem(pemRootCAKey);
        const rootCACert = pki.certificateFromPem(pemRootCA);

        return X509Certificate.createCertificate(options, rootCAKey, csr.publicKey, rootCACert.subject.attributes, csr.subject.attributes);
    }

    public static createCertificateRequest(options: X509CertificateOptions): X509CertificateRequestOutput {
        if (!options.commonName && !options.uri) {
            throw new Error('commonName and uri must be defined.');
        }

        const keyPair = pki.rsa.generateKeyPair(2048);
        const csr = pki.createCertificationRequest();
        csr.publicKey = keyPair.publicKey;
        const attrs = [];
        attrs.push({ name: 'commonName', value: options.commonName });
        if (options.country) attrs.push({ name: 'countryName', value: options.country });
        if (options.state) attrs.push({ shortName: 'ST', value: options.state });
        if (options.locality) attrs.push({ name: 'localityName', value: options.locality });
        if (options.organizationName) attrs.push({ name: 'organizationName', value: options.organizationName });
        csr.setSubject(attrs);

        // sign certification request
        csr.sign(keyPair.privateKey, md.sha256.create());

        return {
            pemPrivateKey: pki.privateKeyToPem(keyPair.privateKey),
            pemPublicKey: pki.publicKeyToPem(keyPair.publicKey),
            pemCSR: pki.certificationRequestToPem(csr)
        };
    }
}

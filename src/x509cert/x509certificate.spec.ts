import { pki } from "node-forge";
import { X509Certificate, X509CertificateOptions } from './x509certificate';

describe("X509Certificate", () => {

    const _pem = {
        rootCA: '-----BEGIN CERTIFICATE-----\r\n' +
        'MIIFkTCCA3mgAwIBAgIUWecpvHryVw/iqb1mOKRjsuvv76YwDQYJKoZIhvcNAQEL\r\n' +
        'BQAwWDELMAkGA1UEBhMCQVUxCzAJBgNVBAgMAldBMQ4wDAYDVQQHDAVQZXJ0aDEM\r\n' +
        'MAoGA1UECgwDRFBVMRAwDgYDVQQLDAdEZXZpY2VzMQwwCgYDVQQDDANkcHUwHhcN\r\n' +
        'MjEwOTI5MDc1NDQyWhcNMzEwOTI3MDc1NDQyWjBYMQswCQYDVQQGEwJBVTELMAkG\r\n' +
        'A1UECAwCV0ExDjAMBgNVBAcMBVBlcnRoMQwwCgYDVQQKDANEUFUxEDAOBgNVBAsM\r\n' +
        'B0RldmljZXMxDDAKBgNVBAMMA2RwdTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCC\r\n' +
        'AgoCggIBANjcaZzh9D8xGgXH8D7Udg7N7xkfD97yIgoGKshOFUK05gY9c88bHQ3X\r\n' +
        '4vHK1Yhm2/NNjdEYSIr9FzLnRy9Sm2RS79VjVHXLG7bp/FGTG6dQLVsDMTk8FXAU\r\n' +
        'lwRoN4wYBumK3FZ283UpLhsG+TRZDn0daYBQ21c5qZAshFK6ok7rCwGJc3MXe81I\r\n' +
        'qDK1dbG57FJ8Lxvg+tUGPUQ7UGtZnPKVKI4o4SOAOGLqnA84sK1MbG3UkvwiFZVN\r\n' +
        '5VqIDwUFdpm9HgPbKuq6kbVkdpgybsnBUZTUvugyk+Y47/7NAqeAyNGJ9RYFORuz\r\n' +
        '57t/qqupKbJHAS60OQqR/4iBZ4QQyIAqCOocwsqRVDYkmqYwSXwIKZhPcpcwv14F\r\n' +
        'u53y4S+OnTB/3U4yC8cYytUw4gpviB0GhYadw6B2HHCMRIY8RBCYGfokpIy7fAq/\r\n' +
        'JDgMIq+u3uNeTKReSo0bIGAz40RDG1MOmc2w7Mf/9o2EYMaOR9TTc/EGimqvMIbE\r\n' +
        'ipMf5UAWMWHp1uaLcwX6hYGCxlz+TcWws6vQZoYLy0FK8LwmtMyc17URtaAcloen\r\n' +
        'VA27IoLC/ysUMC5tN/B8Wht9MW9QzqkwA8FcbWhMVRfTMdyPqTLOPFCrYtphTSEq\r\n' +
        'wsdlgscEpzNE1bcthz310AOws+otS+aMSJ0HF4q/CLDMj1WJ3Bg7AgMBAAGjUzBR\r\n' +
        'MB0GA1UdDgQWBBS3ZBbpH/wH8E9anRbA1hug9aB4FjAfBgNVHSMEGDAWgBS3ZBbp\r\n' +
        'H/wH8E9anRbA1hug9aB4FjAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUA\r\n' +
        'A4ICAQDTyaA7uPb+uW/IKnu7E2hQzU5FjNg2Y+vAmo2z89pzrqN5zbQT9tBgPMnL\r\n' +
        'xxxE9L05uTa45NZDg5b+et2GQzxUb8XMJY8cmdrjZXDG6M3GtZ5SnSBS/V9RdCk8\r\n' +
        'WCGdEVx50XyQpzPpcnpDEBrP7TsLBnSlZhVb0uB8osWZBmMRawgxlEkUW5mzsJo3\r\n' +
        'jxdGBg5McLKpGRgQXi1a7ebIvcSAN3K8Qq8LF8DF0FifbbHcX/g/6yg8IIRyRfcT\r\n' +
        'EllrFILsy2YZua196+r2OIcMtDJ37sjDcXyZh1Lya7FRh08Y6QVeoJnvjd4QL6Ha\r\n' +
        'hTFav6QrFVQhJvqWdr9OZuyaAzbMv6Z56zJHvKDvcfNg4DCVuAqRcyXnPJHtM1Q2\r\n' +
        'rtt171Idi2ewJtHQfzh19mbwftubg6qbK9o5ceJfm2X5AbUDmhoYgDeKc5Imifpg\r\n' +
        '1J2u/nZjjclPJWghmwgDBWWJ5IRDE4F2PqN+gvnLyTT2/DaeBgqNdu9Wznw0DJVC\r\n' +
        'i1lFJRPK+51oApQ7ZhbndMdcXmpzcjw05TtP5MqDvSNzOGK8FAoK+VwWeVJ/Pgg8\r\n' +
        'DFQsMS9It10e9ECchn+1D82aSfw/nASgmB5wQJX785v5RBi7VESp6Z4p7r9c38b+\r\n' +
        'DUCjiUbTJPXlgjsGqVnmGBzc1DJWvGpNaX3CrqTKbMmf3ViL2w==\r\n' +
        '-----END CERTIFICATE-----\r\n',
        rootCAKey: '-----BEGIN RSA PRIVATE KEY-----\r\n' +
        'MIIJKgIBAAKCAgEA2NxpnOH0PzEaBcfwPtR2Ds3vGR8P3vIiCgYqyE4VQrTmBj1z\r\n' +
        'zxsdDdfi8crViGbb802N0RhIiv0XMudHL1KbZFLv1WNUdcsbtun8UZMbp1AtWwMx\r\n' +
        'OTwVcBSXBGg3jBgG6YrcVnbzdSkuGwb5NFkOfR1pgFDbVzmpkCyEUrqiTusLAYlz\r\n' +
        'cxd7zUioMrV1sbnsUnwvG+D61QY9RDtQa1mc8pUojijhI4A4YuqcDziwrUxsbdSS\r\n' +
        '/CIVlU3lWogPBQV2mb0eA9sq6rqRtWR2mDJuycFRlNS+6DKT5jjv/s0Cp4DI0Yn1\r\n' +
        'FgU5G7Pnu3+qq6kpskcBLrQ5CpH/iIFnhBDIgCoI6hzCypFUNiSapjBJfAgpmE9y\r\n' +
        'lzC/XgW7nfLhL46dMH/dTjILxxjK1TDiCm+IHQaFhp3DoHYccIxEhjxEEJgZ+iSk\r\n' +
        'jLt8Cr8kOAwir67e415MpF5KjRsgYDPjREMbUw6ZzbDsx//2jYRgxo5H1NNz8QaK\r\n' +
        'aq8whsSKkx/lQBYxYenW5otzBfqFgYLGXP5NxbCzq9BmhgvLQUrwvCa0zJzXtRG1\r\n' +
        'oByWh6dUDbsigsL/KxQwLm038HxaG30xb1DOqTADwVxtaExVF9Mx3I+pMs48UKti\r\n' +
        '2mFNISrCx2WCxwSnM0TVty2HPfXQA7Cz6i1L5oxInQcXir8IsMyPVYncGDsCAwEA\r\n' +
        'AQKCAgBW/kRXrMTAPMBFpWkYqz4Yvj+2AiHpu5QwFT1AUSJyOgM0aZ51bFkBXqMp\r\n' +
        'f8adCzYcqfXD9UvUhaaywthpgWfYnPSc01XkUu/xNngDeVHUknM/WU57uUCYT4ot\r\n' +
        'OGlgB5tuQEgXX2xWiYh3SxrZBwiq5AuYb9ctbHI65cDHNxs5MUye9zaa6sa9GPJw\r\n' +
        'NR7bhsvoYuy68Etu/SvCnVCrX614GqHENV3rUdpMw/SKnqExQ8ETZfz4q+ugkzj4\r\n' +
        'UjBEQWbMUXMi9N6IfwNIkt6IO2L6CFTjsVxL5U4zQo/z1OXFsAHfHMp2ZO390POa\r\n' +
        '4aHjbt7NJ3Kv+5gOR3cMmWyfK+Rh2HDpeLybKVDtLOvlbcPw4v8uWFQYf0ziD6Nn\r\n' +
        'oBIrSBt1VRMxVTbQn9T49lnk/RD3aK7bqp50GgLTJoL/vqV9cBG35+7NH06ivX77\r\n' +
        'V9uRRGkL2bPC3+29W3uKhjqlpmQytDudAywmAL+wLIPhPCUh8Nx81LDFnQ8SM6W4\r\n' +
        'oxk2Rh4j4K9NNtOpTOhqtk57dGCJUlMdebR178EQJ1+dgghckXe/al4jdI+SfPVQ\r\n' +
        'f8M9EKERRIGClO/OTzikk8rnW/8zsqnkfEKQqQpX9JBcxR4XE9jlt3kAYH9JD6tB\r\n' +
        'ANtaKlFgyKvEi87KqDHuE9eCr4xRWb4Fp38eny6k179c9BSDsQKCAQEA6/CZerr4\r\n' +
        'Rp9vT6TF3TdWAZ7Xibw8UsRGh7KHJWQgLsNAvaTMnhm+4aGBN6stbBgu5Wj8966f\r\n' +
        'sJv0sgyhxvKcCPh06BuJwjfaoCeAXo3KR2thqgzuW2ARC7gbEwOnsTFEznvCkklw\r\n' +
        '+c+AHtEC6klsFxDv/ypsTas1RepKLvujCiC0ZJN1M6Q0NzjrYp1ywnZDPt/o784m\r\n' +
        'm4SdQLv8z3uH1AzpcvTXScaqUgTSj+zqaXBqEcsgd4g8DIloL5NfdLlYJ/r2bRdU\r\n' +
        '8NLX1mrbJtUmUYeQVhdo/ZHKtKTS6RpAo/vYFQtSSagZ8sxiq34nYG2oDcqMMiyg\r\n' +
        'ch9oUiKDJ+hcTwKCAQEA60yMSd23oZVqwVGyqKGOhQ0vH3f82OdjooR9ifNvmR7O\r\n' +
        'UJQX8OsFy1TxyWUGlVhSXvsxZIwWDaDrANEFw52QKNsjQr2pdxPopW0okSOeOQ75\r\n' +
        'RhoAaMPBcCGdRl7/0wpaqp+eV/saSr8uxmkgyilP2Mb4/lykGJlxfDZCgZ0pD18z\r\n' +
        'jz4ghSgmflI36uc/T+G8pbRejZzMEYoVel2FCSY8VXUno4dfprXa6cUefbBbpbQ0\r\n' +
        'nhwmEMW9DeKek9SFxcdhVVW/P5U0cxBZlpukFwZK58fDYx1xubyvkfGfiNlzc3ee\r\n' +
        'oOCGghz4M+QToinqOh0U2xVGtFkGti5mY11VENzuVQKCAQEAg7pLFni5EUUGsqK+\r\n' +
        'TeoNPM5gbGgKDfPDpROJ3NhwF2uwA7G1BDg/mF3BdUE/FPDTjgX15ps6UTJhhd8D\r\n' +
        'm73sXB3Lt6NYYHUqvOwRAbmMTB+p4XVixuV13uMlSpJp18Y4Mkhqs54JU5AEajAr\r\n' +
        'vn7LuH0eYYpf+WUzUxuh22Vm+8qSrOyfLPvqo0JGOULKxcOde8crmGeyqnV6DqBm\r\n' +
        'X7kKdtvWovYMFQa0JSLIJM8TeVboAZM1R0dqr10wLA/N5a9thrTZTMMQC3zMQMxc\r\n' +
        'Guw6fp5/eXGMjrYNRJoZn0em+2cql2VAxhrykdqG5FSEy5OtljWV3JWJ5u2eIu1d\r\n' +
        '6LQUhQKCAQEA3QUyYdAaRXWMqbqMD0pyDRitQun6X+Q5+tZo9cPs9++v7JCvTGX3\r\n' +
        'M1+/HmX/IRmthfp+EuxjarnVBRdSSsUePMJbBL4TCP9ycLFwgaTrYr1l+StDZyU5\r\n' +
        '9pIcoZVqyFnZgJweqJX9xGiBD26AlmTn08BS8tsiaNj5eKufHRD7GK1cSRkagvmL\r\n' +
        '7uxcChLdrbNk+GHMz0iRh4glVKOz6zw3QC6j5T+r4XTBBQVb9sRJ0gTLyBi4yNh1\r\n' +
        'FS3htwrR/U2jZ/z7gEYu1kZtYMMiB16pzb4fEmL+CHHsmTJVoL5ha/zYzFUbA+0i\r\n' +
        'V9vNdW3ZzmyywnfhylY1r7s2AfARj513YQKCAQEAjNSVJdW5Z8drRKcRauU0oc2T\r\n' +
        'PFFjUOJpXJAGn6hxmgqeVEOXGBWHPOWetl/TnKTrsVe8pA8fIktaVsqyjcaXxosy\r\n' +
        'd+9MmURP7vM5hrBEeWM/xoAxyTakf53uqDiStno+yMK0uT1JFfYSknqQjOIygv1w\r\n' +
        'YX4s5n2sG+jwZ5H7KPTBcz81jZyhwLkoSIuYSOyXCPCvUxhA9OqVCwspbh/6xF13\r\n' +
        'FQegctpe2KMuGpQPyDCFVah4bioeHBH7QFa0Cj8ADYa/WJc8J/h8BieSpvsF/wa0\r\n' +
        'ZRL4/DerAfBOq3bg35a4WpH/kBoAt6teRiemFgbgiGBtO1I0IVD6z2wKisjUiA==\r\n' +
        '-----END RSA PRIVATE KEY-----\r\n',
        csr: '-----BEGIN CERTIFICATE REQUEST-----\r\n' +
        'MIICqDCCAZACAQAwYzELMAkGA1UEBhMCQVUxCzAJBgNVBAgMAldBMQ4wDAYDVQQH\r\n' +
        'DAVQZXJ0aDEMMAoGA1UECgwDRFBVMRAwDgYDVQQLDAdEZXZpY2VzMRcwFQYDVQQD\r\n' +
        'DA5kZXYtYXBpLWNsaWVudDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEB\r\n' +
        'ALc0hZmeezQ3/WfmdQaMXzNkdAnY5fAyIFlRW0HyBjSIpPO9OHr0jEe01ShuwDPb\r\n' +
        'GlGDzXbHv0ZsC4Mh/uNIRUDcg4yF6jRwHB+cq0hq9M1D1WPDFvThepjNTYmyg2fA\r\n' +
        'F8Q+lV7QAW9mrGr1aIc3Ipo89BAUGvM8QRhUnro16c/PCMzObuKF+QS/CTYf/gY4\r\n' +
        'VIe/8sXRqaStAgClOWpPeNii8LmjzQYYgcnuTCFFNGmnEkPo8na51s7krqoFMyBu\r\n' +
        '6hfjKylVbMl9EJ7BQzd85DNKpyeM6SLBMI0CIomNCcIcji4u3m/dLD7nD63uSdmJ\r\n' +
        'ifCxYoTf3iLC0WL2PuTD0jsCAwEAAaAAMA0GCSqGSIb3DQEBCwUAA4IBAQBDjll4\r\n' +
        'lX3E4HBsI9mtZbX2U+9PEaMI4cieQ4LvjI21F5vtvSaf/gKM0stRg1rMH5dVKglt\r\n' +
        'kA9FCc4fEFdFJNLV096VSDzP8R3OK7hrRsdfr4xc+ur54XJfrCJlkorY3tLyc1ae\r\n' +
        'Q9BR6gqIbONih6q4DfwExIqDtl60olc8KJy7MRhW/blOLqdCugDRzRS8BMWBK9ol\r\n' +
        'b0VHBk6adJa6R/KHPvDWjjuyLRQwz1S+qwCnZBeubwDx+tUV+V0nAf9de/UMh655\r\n' +
        'BREi3ffhoaY9VBTUQXS/QYLqPWFKo7d/mFuoXsbjm6u68BrkxwDjdt8mUlzZxIVM\r\n' +
        'RQfruHcFqn+YEPi+\r\n' +
        '-----END CERTIFICATE REQUEST-----\r\n'
    };
    it("should create certificate signing request", async () => {
        const csr = X509Certificate.createCertificateRequest({
            commonName: 'Test name',
            uri: 'xyz.com',
            organizationName: 'Test organization'
        } as X509CertificateOptions);
        expect(csr?.pemCSR).not.toBeNull();
        expect(pki.certificationRequestFromPem(csr.pemCSR)).toBeTruthy();
    });

    it("should create self-signed certificate", (done) => {
        const cert = X509Certificate.createSelfSignedCert({
            commonName: 'Test name',
            uri: 'xyz.com',
            organizationName: 'Test organization'
        } as X509CertificateOptions);
        expect(cert?.pemCert).not.toBeNull();

        const caStore = pki.createCaStore();
        const x509Cert = pki.certificateFromPem(cert.pemCert);
        caStore.addCertificate(x509Cert);
        pki.verifyCertificateChain(caStore, [x509Cert], vfd => {
            try {
                expect(vfd).toBeTruthy();
                done();
                return true;
            } catch(err) {
                done(err);
                return false;
            }
        });
    });

    it("should create a certificate signed by rootCA", (done) => {
        const pemRootCA = _pem.rootCA;
        const pemRootCAKey = _pem.rootCAKey;
        const cert = X509Certificate.createIntermediateCert(pemRootCA, pemRootCAKey, {
            commonName: 'Test name',
            uri: 'xyz.com',
            organizationName: 'Test organization'
        } as X509CertificateOptions);
        expect(cert?.pemCert).not.toBeNull();

        const caStore = pki.createCaStore();
        const x509Cert = pki.certificateFromPem(cert.pemCert);
        caStore.addCertificate(x509Cert);
        pki.verifyCertificateChain(caStore, [x509Cert], vfd => {
            try {
                expect(vfd).toBeTruthy();
                done();
                return true;
            } catch(err) {
                done(err);
                return false;
            }
        });
    });

    it("should create a certificate signed by rootCA", (done) => {
        const pemRootCA = _pem.rootCA;
        const pemRootCAKey = _pem.rootCAKey;
        const pemCSR = _pem.csr;
        const cert = X509Certificate.createCertificateByCSR(pemRootCA, pemRootCAKey, pemCSR, {
            commonName: 'Test name',
            uri: 'xyz.com',
            organizationName: 'Test organization'
        } as X509CertificateOptions);
        expect(cert?.pemCert).not.toBeNull();

        const caStore = pki.createCaStore();
        const x509Cert = pki.certificateFromPem(cert.pemCert);
        caStore.addCertificate(x509Cert);
        pki.verifyCertificateChain(caStore, [x509Cert], vfd => {
            try {
                expect(vfd).toBeTruthy();
                done();
                return true;
            } catch(err) {
                done(err);
                return false;
            }
        });
    });
});

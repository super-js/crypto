import {X509} from "./x-509";

describe("x-509", () => {
    const x509Cert = "-----BEGIN CERTIFICATE-----\n" +
        "MIICHTCCAaOgAwIBAAIBATAKBggqhkjOPQQDAzBtMSEwHwYDVQQDDBhqYWt1Yi10\n" +
        "aGUtdW5pdGVyLXJvb3QtY2ExCzAJBgNVBAYTAkFVMQwwCgYDVQQKDANEUFUxEDAO\n" +
        "BgNVBAsMB0RldmljZXMxDjAMBgNVBAcMBVBlcnRoMQswCQYDVQQIDAJXQTAiGA8y\n" +
        "MDIyMDEyMDE2NTA2NFoYDzIwMjYwMzIwMTY1MDY0WjBtMSEwHwYDVQQDDBhqYWt1\n" +
        "Yi10aGUtdW5pdGVyLXJvb3QtY2ExCzAJBgNVBAYTAkFVMQwwCgYDVQQKDANEUFUx\n" +
        "EDAOBgNVBAsMB0RldmljZXMxDjAMBgNVBAcMBVBlcnRoMQswCQYDVQQIDAJXQTB2\n" +
        "MBAGByqGSM49AgEGBSuBBAAiA2IABAleobmu2vOiybUCzaIPpQtzXAWav01kL+Xi\n" +
        "Chae/9GBNjk/6Fgm7+De/S/Nxtq3Mzrsp2whq+DxQCMNKFyv0OmtfzjR1Y2ozsUS\n" +
        "699ISnqJHckPMy2PDGUyt96Cej5JE6MTMBEwDwYDVR0TAQH/BAUwAwIBAjAKBggq\n" +
        "hkjOPQQDAwNoADBlAjBpxo5Uu7g61KJBpqxyabeUXXtssRhAQY2Df/rQx34pctN/\n" +
        "kVVe6L6AspGAOL0bXbICMQDvABTKlP6/J6CTjvs5VmEWlcUhLbub4sq/3z2WYSKa\n" +
        "03ETP0ORfhcaJlsch/ro2D0=\n" +
        "-----END CERTIFICATE-----\n";

    it('should read certificate details', () => {
        const certInfo = X509.getCertificateInfo(x509Cert);
        console.log(certInfo);
    });
});
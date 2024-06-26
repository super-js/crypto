import {KDID_KEY_USAGE_INDICATOR, Tr31KeyDerivation} from "./tr-31-key-derivation";
import {AesCmac} from "../../utils";

describe("tr-31-key-derivation", function () {

    const aesCmac = new AesCmac(Buffer.alloc(16, 0));

    it("should create an authentication MAC key", () => {
        const keyBlockAuthenticationKey = Tr31KeyDerivation.build({
            aesCmac,
            keyUsageIndicator: KDID_KEY_USAGE_INDICATOR.MAC
        }).calculateCmac();


        // console.log(keyBlockAuthenticationKey.toString('hex'));
        // console.log(keyBlockAuthenticationKey);

        expect(Buffer.isBuffer(keyBlockAuthenticationKey)).toBeTruthy();

    });
});
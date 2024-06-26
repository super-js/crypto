import {Tr31Reader} from "./tr-31-reader";
import {TestKeyBlock} from "./key-blocks/test-key-block";
import {randomBytes} from "crypto";


describe("tr-31-reader", function () {

    const kbpk = randomBytes(16);
    const data = randomBytes(16);

    it("should read a TR-31 block", () => {

        const testBlock = new TestKeyBlock({
            keyBlockProtectionKey: kbpk, data
        });
        console.log(testBlock.keyBlock.block)
        const tr31Reader = Tr31Reader.build({
            keyBlockProtectionKey: kbpk,
            keyBlock: testBlock.keyBlock.block
        });

        expect(tr31Reader).toBeInstanceOf(Tr31Reader);
        expect(tr31Reader.getData().key).toEqual(data);

        tr31Reader.dispose();

        expect(tr31Reader.getData().key).not.toEqual(data);
    });
});
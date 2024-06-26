import {TestKeyBlock} from "./test-key-block";

describe("test-key-block", () => {
    it("should work", () => {
        const a = new TestKeyBlock({
            keyBlockProtectionKey: Buffer.from('88E1AB2A2E3DD38C1FA039A536500CC8A87AB9D62DC92C01058FA79F44657DE6', 'hex'),
            data: Buffer.from('3F419E1CB7079442AA37474C2EFBF8B8', 'hex')
        });

        console.log(a.keyBlock)

        expect(a).toBeInstanceOf(TestKeyBlock);
    })
})
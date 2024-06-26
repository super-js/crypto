import {Tr31Builder} from "./tr-31-builder";
import {
    KEY_BLOCK_HEADER_ALGORITHM, KEY_BLOCK_HEADER_EXPORTABILITY,
    KEY_BLOCK_HEADER_KEY_USAGE,
    KEY_BLOCK_HEADER_MODE_OF_USE,
    Tr31Header
} from "./header";
import {KEY_BLOCK_HEADER_CONTEXT} from "./header/key-context";
import {ASYMMETRIC_KEY_LIFE, AsymmetricKeyLife} from "./header/optional-blocks";

describe("tr-31-block", function () {
    it("should build a TR-31 block", () => {

        const tr31Header = Tr31Header.build()
            .setKeyUsage(KEY_BLOCK_HEADER_KEY_USAGE.B0)
            .setAlgorithm(KEY_BLOCK_HEADER_ALGORITHM.EC)
            .setModeOfUse(KEY_BLOCK_HEADER_MODE_OF_USE.NO_RESTRICTIONS)
            .setKeyVersion('1')
            .setExportability(KEY_BLOCK_HEADER_EXPORTABILITY.NON_EXPORTABLE)
            .setKeyContext(KEY_BLOCK_HEADER_CONTEXT.STORAGE)
            .addOptionalBlock(new AsymmetricKeyLife({
                asymmetricKeyLife: ASYMMETRIC_KEY_LIFE.EPHEMERAL
            }));

        const tr31Builder = Tr31Builder.build({
            keyBlockProtectionKey: Buffer.alloc(16, 0),
        });

        tr31Builder.setData(Buffer.alloc(16, 9));
        tr31Builder.setHeader(tr31Header);
        // console.log(tr31Builder.final())

        // console.log(tr31Builder.asString);
        // console.log(tr31Builder.buffer); <Buffer c2 d2 b0 90 4d b8 c6 d8 d9 bf e3 d2 52 52 70 41>
        //console.log(tr31Builder.getAuthenticationMac());

        expect(tr31Builder).toBeInstanceOf(Tr31Builder);
    });
});
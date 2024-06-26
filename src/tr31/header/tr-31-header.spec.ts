import {Tr31Header} from "./tr-31-header";
import {KEY_BLOCK_HEADER_KEY_USAGE} from "./usage";
import {KEY_BLOCK_HEADER_ALGORITHM} from "./algorithm";
import {KEY_BLOCK_HEADER_MODE_OF_USE} from "./mode-of-use";
import {KEY_BLOCK_HEADER_EXPORTABILITY} from "./exportability";
import {KEY_BLOCK_HEADER_CONTEXT} from "./key-context";
import {ASYMMETRIC_KEY_LIFE, AsymmetricKeyLife} from "./optional-blocks";

describe("tr-31-header", function () {
    it("should create a header", () => {
        const keyBlockAuthenticationKey = Tr31Header
            .build()
            .setKeyUsage(KEY_BLOCK_HEADER_KEY_USAGE.B0)
            .setAlgorithm(KEY_BLOCK_HEADER_ALGORITHM.AES)
            .setModeOfUse(KEY_BLOCK_HEADER_MODE_OF_USE.NO_RESTRICTIONS)
            .setKeyVersion("1")
            .setExportability(KEY_BLOCK_HEADER_EXPORTABILITY.NON_EXPORTABLE)
            .setKeyBlockLength(8000)
            .setKeyContext(KEY_BLOCK_HEADER_CONTEXT.STORAGE)
            .addOptionalBlock(new AsymmetricKeyLife({
                asymmetricKeyLife: ASYMMETRIC_KEY_LIFE.EPHEMERAL
            }))
            .printOptionalHeaders()

        //console.log(keyBlockAuthenticationKey.ascii);

    });
});
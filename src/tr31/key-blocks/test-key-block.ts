import {IKeyBlockOptions, KeyBlock} from "./key-block";
import * as header from "../header";
import {ASYMMETRIC_KEY_LIFE, AsymmetricKeyLife, TDEADuktptId} from "../header/optional-blocks";

export class TestKeyBlock extends KeyBlock {
    constructor(options: IKeyBlockOptions) {
        super(options);
    }

    protected get keyUsage() {
        return header.KEY_BLOCK_HEADER_KEY_USAGE.P0;
    }

    protected get algorithm() {
        return header.KEY_BLOCK_HEADER_ALGORITHM.AES;
    }

    protected get modeOfUse() {
        return header.KEY_BLOCK_HEADER_MODE_OF_USE.ENCRYPT_WRAP_ONLY;
    }

    protected get keyVersion() {
        return header.KEY_BLOCK_HEADER_KEY_VERSION_NUMBER.NONE;
    }

    protected get exportability() {
        return header.KEY_BLOCK_HEADER_EXPORTABILITY.EXPORTABLE;
    }

    protected get keyContext() {
        return header.KEY_BLOCK_HEADER_CONTEXT.STORAGE;
    }

    protected get optionalBlocks() {
        return [
            // new AsymmetricKeyLife({
            //     asymmetricKeyLife: ASYMMETRIC_KEY_LIFE.EPHEMERAL
            // }),
            new TDEADuktptId({
                keySetId: '1234567890',
                deviceId: '12345'
            })
        ]
    }

}
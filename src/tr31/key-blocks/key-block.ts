import * as header from "../header";
import {ITr31FinalResult, Tr31Builder} from "../tr-31-builder";

export interface IKeyBlockOptions {
    keyBlockProtectionKey: Buffer;
    data: Buffer | string;
}

export abstract class KeyBlock {

    private readonly _keyBlock: ITr31FinalResult;

    protected constructor(options: IKeyBlockOptions) {
        const tr31Builder = Tr31Builder.build({
            keyBlockProtectionKey: options.keyBlockProtectionKey
        })

        tr31Builder.setHeader(this._getHeader());
        tr31Builder.setData(options.data);

        this._keyBlock = tr31Builder.final();
    }

    private _getHeader(): header.Tr31Header {
        return header.Tr31Header.build()
            .setVersionId(this.keyVersionId)
            .setKeyUsage(this.keyUsage)
            .setAlgorithm(this.algorithm)
            .setModeOfUse(this.modeOfUse)
            .setKeyVersion(this.keyVersion)
            .setExportability(this.exportability)
            .setKeyContext(this.keyContext)
            .addOptionalBlocks(this.optionalBlocks)
    }

    // Header fields
    protected get keyVersionId(): header.KEY_BLOCK_HEADER_VERSION {
        return header.KEY_BLOCK_HEADER_VERSION.D;
    }
    protected abstract get keyUsage(): header.KEY_BLOCK_HEADER_KEY_USAGE;
    protected abstract get algorithm(): header.KEY_BLOCK_HEADER_ALGORITHM;
    protected abstract get modeOfUse(): header.KEY_BLOCK_HEADER_MODE_OF_USE;
    protected abstract get keyVersion(): header.KEY_BLOCK_HEADER_KEY_VERSION_NUMBER;
    protected abstract get exportability(): header.KEY_BLOCK_HEADER_EXPORTABILITY;
    protected abstract get keyContext(): header.KEY_BLOCK_HEADER_CONTEXT;
    protected get optionalBlocks(): header.OptionalBlock[] {
        return [];
    }

    get keyBlock(): ITr31FinalResult {
        return this._keyBlock;
    }
}
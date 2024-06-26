import {OPTIONAL_BLOCK_ID, OptionalBlock} from "../optional-block";
import {lengthToAsciiDecimal} from "../../../utils";

export interface IPaddingBlockOptions {
    keyBlockHeaderBuffer: Buffer;
}

export class PaddingBlock extends OptionalBlock {

    public static STATIC_BLOCK_BYTE_LENGTH = 4;

    constructor(options: IPaddingBlockOptions) {

        const headerLength = options.keyBlockHeaderBuffer.length;
        let noOfBytesToBePadded = 0;

        while((headerLength + noOfBytesToBePadded + PaddingBlock.STATIC_BLOCK_BYTE_LENGTH) % 16)             noOfBytesToBePadded++;

        super({
            blockId: OPTIONAL_BLOCK_ID.PADDING_BLOCK,
            data: Buffer.alloc(noOfBytesToBePadded, 0x30, 'ascii')
        });
    }
}
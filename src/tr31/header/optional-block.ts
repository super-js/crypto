import {bufferToAscii} from "../../utils";

export const KEY_BLOCK_HEADER_KEY_OPT_BLOCK_NO_OFFSET = 12;

export enum OPTIONAL_BLOCK_ID {
    ASYMMETRIC_KEY_LIFE_ATTRIBUTE = 0x414C,
    BDKI_DUKPT = 0x4249,
    ASYMMETRIC_CERTIFICATE = 0x4354,
    ALLOWED_DERIVATIONS = 0x4441,
    FLAGS = 0x464C,
    ALGORITHM_HMAC = 0x484D,
    AES_DUKPT_ID = 0x494B,
    KCV_FOR_WRAPPED_KEY = 0x4B43,
    KVC_FOR_KBPK = 0x4B50,
    TDEA_DUKPT_ID = 0x4B53,
    KEY_BLOCK_VALUES_VERSION = 0x4B56,
    LABEL = 0x4C42,
    PADDING_BLOCK = 0x5042,
    KCV_FOR_KBPK_PROTECTION = 0x504B,
    KEY_TIME_OF_CREATION = 0x5443,
    KEYBLOCK_TIME_OF_CREATION = 0x5453,
    WRAPPING_PEDIGREE = 0x5750
}

export interface IOptionalBlockConstructorOptions {
    blockId: OPTIONAL_BLOCK_ID;
    data: Buffer;
}

export class OptionalBlock {

    public static OPTIONAL_BLOCK_ID_SIZE = 2;
    public static OPTIONAL_BLOCK_STANDARD_LENGTH_SIZE = 2;

    private readonly _blockId: OPTIONAL_BLOCK_ID;
    private readonly _blockLength: number;
    private readonly _blockData: Buffer;

    private readonly _blockBuffer = Buffer.alloc(0);

    constructor(options: IOptionalBlockConstructorOptions) {
        this._blockId = options.blockId;
        this._blockData = options.data;
        this._blockLength = OptionalBlock.OPTIONAL_BLOCK_ID_SIZE
            + OptionalBlock.OPTIONAL_BLOCK_STANDARD_LENGTH_SIZE
            + this._blockData.length;

        this._blockBuffer = Buffer.alloc(this._blockLength);

        this._writeBlockId();
        this._writeBlockLength();
        this._writeData();
    }

    public static isValidBlockId(blockId: number) {
        return !!OPTIONAL_BLOCK_ID[blockId];
    }

    public static fromOptionalBlocksBuffer(optionalBlocksBuffer: Buffer): OptionalBlock[] {

        const blockBuffer = Buffer.from(optionalBlocksBuffer);

        let currentStartIndex = 0;
        let optionalBlocks = [];
        let blockId = blockBuffer.readUInt16BE(0);

        do {
            const currentBlockLength = parseInt(bufferToAscii(blockBuffer.slice(currentStartIndex + 2, currentStartIndex + 4)), 16);
            const currentBlockBuffer = Buffer.from(blockBuffer.slice(currentStartIndex + 4, currentStartIndex + currentBlockLength));

            optionalBlocks.push(new OptionalBlock({
                blockId,
                data: currentBlockBuffer
            }));

            currentStartIndex = currentStartIndex + currentBlockLength;
            blockId = blockBuffer.readUInt16BE(currentStartIndex);

        } while(OptionalBlock.isValidBlockId(blockId));

        return optionalBlocks;
    }

    private _writeBlockId() {
        this._blockBuffer.writeUInt16BE(this._blockId, 0);
    }

    private _writeBlockLength() {
        this._blockBuffer.write(this._blockBuffer.length.toString(16).padStart(2, '0'), 2,'ascii');
    }

    private _writeData() {
        this._blockData.copy(
            this._blockBuffer,
            OptionalBlock.OPTIONAL_BLOCK_ID_SIZE + OptionalBlock.OPTIONAL_BLOCK_STANDARD_LENGTH_SIZE,
            0
            );
    }

    public get blockId(): OPTIONAL_BLOCK_ID {
        return this._blockId;
    }

    get buffer(): Buffer {
        return Buffer.from(this._blockBuffer);
    }

    get ascii(): string {
        return bufferToAscii(this.buffer);
    }
}
import {KEY_BLOCK_HEADER_VERSION, KEY_BLOCK_HEADER_VERSION_OFFSET, TKeyBlockHeaderVersion} from "./version";
import {KEY_BLOCK_HEADER_KEY_USAGE, KEY_BLOCK_HEADER_USAGE_OFFSET, TKeyBlockHeaderKeyUsage} from "./usage";
import {KEY_BLOCK_HEADER_ALGORITHM, KEY_BLOCK_HEADER_ALGORITHM_OFFSET, TKeyBlockHeaderAlgorithm} from "./algorithm";
import {KEY_BLOCK_HEADER_MODE_OF_USE, KEY_BLOCK_HEADER_MODE_OFFSET, TKeyBlockHeaderModeOfUse} from "./mode-of-use";
import {KEY_BLOCK_HEADER_KEY_VERSION_NUMBER, KEY_BLOCK_HEADER_KEY_VERSION_OFFSET} from "./key-version-number";
import {
    KEY_BLOCK_HEADER_EXPORTABILITY,
    KEY_BLOCK_HEADER_KEY_EXPORTABILITY_OFFSET,
    TKeyBlockHeaderExportability
} from "./exportability";
import {
    ASCII_ZERO,
    bufferToAscii,
    characterCodesToDecimal,
    lengthToAsciiCodes,
    lengthToAsciiDecimal
} from "../../utils";
import {Tr31Authentication} from "../authentication";
import {KEY_BLOCK_HEADER_LENGTH_OFFSET} from "./key-block-length";
import {KEY_BLOCK_HEADER_KEY_OPT_BLOCK_NO_OFFSET, OptionalBlock} from "./optional-block";
import {KEY_BLOCK_HEADER_CONTEXT, KEY_BLOCK_HEADER_CONTEXT_OFFSET, TKeyBlockHeaderKeyContext} from "./key-context";
import {PaddingBlock} from "./optional-blocks";


export class Tr31Header {

    private _buffer: Buffer = Buffer.alloc(16);

    private _versionId: KEY_BLOCK_HEADER_VERSION;
    private _keyBlockLength: number;
    private _keyUsage: KEY_BLOCK_HEADER_KEY_USAGE;
    private _algorithm: KEY_BLOCK_HEADER_ALGORITHM;
    private _modeOfUse: KEY_BLOCK_HEADER_MODE_OF_USE;
    private _keyVersionNumber: KEY_BLOCK_HEADER_KEY_VERSION_NUMBER;
    private _exportability: KEY_BLOCK_HEADER_EXPORTABILITY;
    private _keyContext: KEY_BLOCK_HEADER_CONTEXT;

    private _optionalBlocks: OptionalBlock[] = [];

    constructor(keyBlock?: string) {
        if(keyBlock) {

            const keyBlockBuffer = Buffer.from(keyBlock, 'ascii');
            this._buffer = Buffer.from(keyBlockBuffer.slice(0, 16));

            if(this.noOfOptionalBlocks > 0) {
                // console.log(OptionalBlock.fromOptionalBlocksBuffer(keyBlockBuffer.slice(16)))
                this.addOptionalBlocks(OptionalBlock.fromOptionalBlocksBuffer(keyBlockBuffer.slice(16)));
            }

        } else {
            this.setVersionId(KEY_BLOCK_HEADER_VERSION.D);
            this.setDefaultStaticValues();
        }
    }

    public static build(): Tr31Header {
        return new Tr31Header();
    }

    public static buildFromKeyBlock(keyBlock: string) {
        return new Tr31Header(keyBlock);
    }

    private setDefaultStaticValues() {
        // Reserved for future use
        this._setSeparator();
        this.setKeyVersion(KEY_BLOCK_HEADER_KEY_VERSION_NUMBER.NONE);
        this._setNoOfOptionalBlocks();
    }

    private _setNoOfOptionalBlocks() {
        this._buffer.writeUInt16BE(lengthToAsciiDecimal(this._optionalBlocks.length), KEY_BLOCK_HEADER_KEY_OPT_BLOCK_NO_OFFSET);
    }

    private _setSeparator() {
        this._buffer.writeUInt8(ASCII_ZERO, 15);
    }

    private _addOptionalBlock(optionalBlock: OptionalBlock) {
        this._optionalBlocks.push(optionalBlock);
        this._buffer = Buffer.concat([
            this._buffer,
            optionalBlock.buffer
        ]);
        this._setNoOfOptionalBlocks();
    }

    public updatePadding() {
        if(this.buffer.length % 16) {
            this._addOptionalBlock(new PaddingBlock({
                keyBlockHeaderBuffer: this.buffer
            }))
        }
    }

    setVersionId(versionId: KEY_BLOCK_HEADER_VERSION): Tr31Header {
        this._versionId = versionId;

        this._buffer.writeUInt8(this._versionId, KEY_BLOCK_HEADER_VERSION_OFFSET);

        return this;
    }

    setKeyBlockLength(keyLength: number): Tr31Header {

        this._keyBlockLength = this.length + keyLength + Tr31Authentication.MAC_BLOCK_HEX_LENGTH;

        this._buffer.writeUInt32BE(lengthToAsciiDecimal(this._keyBlockLength, {
            noOfCharacters: 4
        }), KEY_BLOCK_HEADER_LENGTH_OFFSET);

        return this;
    }

    setKeyUsage(keyUsage: KEY_BLOCK_HEADER_KEY_USAGE): Tr31Header {
        this._keyUsage = keyUsage;

        this._buffer.writeUInt16BE(this._keyUsage, KEY_BLOCK_HEADER_USAGE_OFFSET);

        return this;
    }

    setAlgorithm(algorithm: KEY_BLOCK_HEADER_ALGORITHM): Tr31Header {
        this._algorithm = algorithm;

        this._buffer.writeUInt8(this._algorithm, KEY_BLOCK_HEADER_ALGORITHM_OFFSET);

        return this;
    }

    setModeOfUse(modeOfUse: KEY_BLOCK_HEADER_MODE_OF_USE): Tr31Header {
        this._modeOfUse = modeOfUse;

        this._buffer.writeUInt8(this._modeOfUse, KEY_BLOCK_HEADER_MODE_OFFSET);

        return this;
    }

    setKeyVersion(keyVersionNumber: KEY_BLOCK_HEADER_KEY_VERSION_NUMBER | string): Tr31Header {

        if(keyVersionNumber === KEY_BLOCK_HEADER_KEY_VERSION_NUMBER.NONE) {
            this._keyVersionNumber = keyVersionNumber;
        } else {
            this._keyVersionNumber = characterCodesToDecimal([
                KEY_BLOCK_HEADER_KEY_VERSION_NUMBER.VERSION_CHAR,
                keyVersionNumber.toString().charCodeAt(0)
            ]);
        }

        this._buffer.writeUInt16BE(this._keyVersionNumber, KEY_BLOCK_HEADER_KEY_VERSION_OFFSET);

        return this;
    }

    setExportability(exportability: KEY_BLOCK_HEADER_EXPORTABILITY): Tr31Header {
        this._exportability = exportability;

        this._buffer.writeUInt8(this._exportability, KEY_BLOCK_HEADER_KEY_EXPORTABILITY_OFFSET);

        return this;
    }

    setKeyContext(keyContext: KEY_BLOCK_HEADER_CONTEXT): Tr31Header {
        this._keyContext = keyContext;

        this._buffer.writeUInt8(this._keyContext, KEY_BLOCK_HEADER_CONTEXT_OFFSET);

        return this;
    }

    addOptionalBlock(optionalBlock: OptionalBlock): Tr31Header {
        this._addOptionalBlock(optionalBlock);
        return this;
    }

    addOptionalBlocks(optionalBlocks: OptionalBlock[]): Tr31Header {
        optionalBlocks.forEach(optionalBlock => this.addOptionalBlock(optionalBlock));
        return this;
    }

    printOptionalHeaders(): Tr31Header {
        console.log(
            this._optionalBlocks.map(optionalHeader => (
                `${optionalHeader.ascii}`
            )).join('\n')
        )
        return this;
    }

    clear(): void {
        this._buffer.fill(0);
    }

    get versionId(): TKeyBlockHeaderVersion {
        return KEY_BLOCK_HEADER_VERSION[this._buffer.readUInt8(KEY_BLOCK_HEADER_VERSION_OFFSET)] as TKeyBlockHeaderVersion;
    }

    get blockLengthAscii(): string {
        return bufferToAscii(this._buffer.slice(KEY_BLOCK_HEADER_LENGTH_OFFSET, KEY_BLOCK_HEADER_LENGTH_OFFSET + 4));
    }

    get blockLength(): number {
        return parseInt(this.blockLengthAscii);
    }

    get keyUsage(): TKeyBlockHeaderKeyUsage {
        return KEY_BLOCK_HEADER_KEY_USAGE[this._buffer.readUInt16BE(KEY_BLOCK_HEADER_USAGE_OFFSET)] as TKeyBlockHeaderKeyUsage;
    }

    get algorithm(): TKeyBlockHeaderAlgorithm {
        return KEY_BLOCK_HEADER_ALGORITHM[this._buffer.readUInt8(KEY_BLOCK_HEADER_ALGORITHM_OFFSET)] as TKeyBlockHeaderAlgorithm;
    }

    get modeOfUse(): TKeyBlockHeaderModeOfUse {
        return KEY_BLOCK_HEADER_MODE_OF_USE[this._buffer.readUInt8(KEY_BLOCK_HEADER_MODE_OFFSET)] as TKeyBlockHeaderModeOfUse;
    }

    get keyVersion(): string {
        return this._buffer.slice(KEY_BLOCK_HEADER_KEY_VERSION_OFFSET, KEY_BLOCK_HEADER_KEY_VERSION_OFFSET + 2).toString('ascii');
    }

    get exportability(): TKeyBlockHeaderExportability {
        return KEY_BLOCK_HEADER_EXPORTABILITY[this._buffer.readUInt8(KEY_BLOCK_HEADER_KEY_EXPORTABILITY_OFFSET)] as TKeyBlockHeaderExportability;
    }

    get noOfOptionalBlocks(): number {
        return parseInt(bufferToAscii(this._buffer.slice(KEY_BLOCK_HEADER_KEY_OPT_BLOCK_NO_OFFSET, KEY_BLOCK_HEADER_KEY_OPT_BLOCK_NO_OFFSET + 2)))
    }

    get keyContext(): TKeyBlockHeaderKeyContext {
        return KEY_BLOCK_HEADER_CONTEXT[this._buffer.readUInt8(KEY_BLOCK_HEADER_CONTEXT_OFFSET)] as TKeyBlockHeaderKeyContext;
    }

    get buffer(): Buffer {
        return Buffer.from(this._buffer);
    }

    get length(): number {
        return this.buffer.length;
    }

    get ascii(): string {
        return bufferToAscii(this.buffer);
    }
}
import {randomBytes} from "crypto";
import {AesCmac, bufferToHex} from "../../utils";
import {KDID_KEY_USAGE_INDICATOR, Tr31KeyDerivation} from "../key-derivation";
import {CipherDecrypt, CipherEncrypt} from "../../cipher";
import {KEY_BLOCK_HEADER_VERSION, TKeyBlockHeaderAlgorithm, Tr31Header} from "../header";

export interface ITr31DataOptions {
    aesCmac: AesCmac;
}

export interface IExistingKeyBlockOptions {
    keyBlock: string;
    mac: Buffer;
    keyBlockHeader: Tr31Header;
}


export class Tr31Data {

    public static KEY_LENGTH_SIZE = 2;

    private readonly _keyBlockEncryptionKey: Buffer;

    private _keyBuffer: Buffer = Buffer.alloc(0);
    private _paddingBuffer: Buffer = Buffer.alloc(0);

    constructor(options: ITr31DataOptions, existingKeyBlockOptions?: IExistingKeyBlockOptions) {

        this._keyBlockEncryptionKey = Tr31KeyDerivation.build({
            aesCmac: options.aesCmac,
            keyUsageIndicator: KDID_KEY_USAGE_INDICATOR.ENCRYPTION
        }).calculateCmac();

        if(existingKeyBlockOptions) {

            const {keyBlock, mac, keyBlockHeader} = existingKeyBlockOptions;

            const decryptedData = this._decryptData(keyBlock, mac, keyBlockHeader.ascii.length);
            const actualKeyLength = Tr31Data._getKeyWithoutPaddingBitLength(decryptedData) / 8;

            this._keyBuffer = Buffer.from(decryptedData.slice(0, actualKeyLength + 2));
            this._paddingBuffer = Buffer.from(decryptedData.slice(actualKeyLength + 2));
        }
    }

    public static buildFromKeyBlock(options: ITr31DataOptions, existingKeyBlockOptions: IExistingKeyBlockOptions): Tr31Data {
        return new Tr31Data(options, existingKeyBlockOptions);
    }

    private static _getKeyWithoutPaddingBitLength(keyBuffer: Buffer): number {
        return parseInt(keyBuffer.slice(0, 2).toString('hex'), 16);
    }

    public setData(data: Buffer | string): Tr31Data {
        const dataBuffer = typeof data === "string" ? Buffer.from(data, 'hex') : data;

        const lengthBuffer = Buffer.alloc(Tr31Data.KEY_LENGTH_SIZE);
        lengthBuffer.writeUInt16BE(dataBuffer.length * 8, 0);

        this._keyBuffer = Buffer.concat([
            lengthBuffer, dataBuffer
        ]);

        return this;
    }

    private _decryptData(keyBlock: string, mac: Buffer, headerLengthInBytes: number) {

        const buffer = Buffer.from(keyBlock.slice(headerLengthInBytes, keyBlock.length - 32), 'hex');

        const options = {
            key: this._keyBlockEncryptionKey,
            iv: mac,
            data: buffer
        }

        switch (this._keyBlockEncryptionKey.length) {
            case 16:
                return CipherDecrypt.decryptWithAes128CBC(options);
            case 24:
                return CipherDecrypt.decryptWithAes192CBC(options);
            case 32:
                return CipherDecrypt.decryptWithAes256CBC(options);
        }
    }

    public setPadding(wrappedKeyAlgorithm: TKeyBlockHeaderAlgorithm, keyBlockVersionId = KEY_BLOCK_HEADER_VERSION.D): Tr31Data {

        if(this._keyBuffer.length === 0) return this;

        let paddingBuffer = Buffer.alloc(0);

        // Key Obfuscation
        if(wrappedKeyAlgorithm === "AES") {
            paddingBuffer = randomBytes(32 - this.keyByteLength);
        } else if(wrappedKeyAlgorithm === "TDEA") {
            paddingBuffer = randomBytes(24 - this.keyByteLength);
        }

        //Cipher block padding - Only AES supported
        if(keyBlockVersionId === KEY_BLOCK_HEADER_VERSION.D) {

            let noOfBytesToBePadded = 0;
            while((paddingBuffer.length + this._keyBuffer.length + noOfBytesToBePadded) % 16) noOfBytesToBePadded++;

            paddingBuffer = Buffer.concat([
                paddingBuffer,
                randomBytes(noOfBytesToBePadded)
            ]);
        }

        this._paddingBuffer = paddingBuffer;

        return this;
    }

    public encryptData(mac: Buffer): Buffer {
        const options = {
            key: this._keyBlockEncryptionKey,
            iv: mac,
            data: this.buffer
        }

        switch (this._keyBlockEncryptionKey.length) {
            case 16:
                return CipherEncrypt.encryptWithAes128CBC(options);
            case 24:
                return CipherEncrypt.encryptWithAes192CBC(options);
            case 32:
                return CipherEncrypt.encryptWithAes256CBC(options);
        }
    }

    clear(): void {
        this._keyBuffer.fill(0);
        this._keyBlockEncryptionKey.fill(0);
        this._paddingBuffer.fill(0);
    }

    public get hasData(): boolean {
        return this._keyBuffer.length > 0;
    }

    public get keyBuffer(): Buffer {
        return Buffer.from(this._keyBuffer);
    }

    public get keyPaddingBuffer(): Buffer {
        return Buffer.from(this._paddingBuffer);
    }

    public get buffer(): Buffer {
        return Buffer.concat([
            this._keyBuffer,
            this._paddingBuffer
        ])
    }

    public get key(): Buffer {
        return Buffer.from(this._keyBuffer.slice(2, 2 + this._keyBuffer.length))
    }

    public get keyHex(): string {
        return bufferToHex(this.key);
    }


    public get hex(): string {
        return `${this.keyWithLengthHex}${this.paddingHex}`;
    }

    public get keyWithLengthHex(): string {
        return bufferToHex(this._keyBuffer);
    }

    public get paddingHex(): string {
        return bufferToHex(this._paddingBuffer);
    }

    public get hexLength(): number {
        return this.hex.length;
    }

    public get byteLength(): number {
        return this._keyBuffer.length + this._paddingBuffer.length;
    }

    public get bitsLength(): number {
        return (this._keyBuffer.length + this._paddingBuffer.length) * 8;
    }

    public get keyBitLength(): number {
        return Math.max((this._keyBuffer.length - Tr31Data.KEY_LENGTH_SIZE) * 8, 0);
    }

    public get keyByteLength(): number {
        return Math.max((this._keyBuffer.length - Tr31Data.KEY_LENGTH_SIZE), 0);
    }

    public get paddingBitLength(): number {
        return this._paddingBuffer.length * 8;
    }

    public get paddingByteLength(): number {
        return this._paddingBuffer.length;
    }

    public get keyWithoutPaddingBitLength(): number {
        return Tr31Data._getKeyWithoutPaddingBitLength(this._keyBuffer);
    }

    public get keyWithoutPaddingByteLength(): number {
        return this.keyWithoutPaddingBitLength / 8;
    }
}
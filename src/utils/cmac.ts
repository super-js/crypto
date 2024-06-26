import { createCipheriv } from 'crypto';
import { Bitwise } from './bitwise';
import {INVALID_AES_KEY_SIZE} from "./errors";

export interface AesCmacAlgorithms {
    [byteLength: number]: string
}

export interface ICMACSubKeys {
    k1: Buffer;
    k2: Buffer;
}

export class AesCmac {

    private readonly algorithms: AesCmacAlgorithms = {
        16: `aes-128-cbc`,
        24: `aes-192-cbc`,
        32: `aes-256-cbc`,
    };

    private readonly blockSize = 16;
    private readonly algorithm: string;

    private readonly _aesKeyLength: number;
    private readonly _subKeys: ICMACSubKeys;

    public static CONSTANT_R128 = Buffer.from(`00000000000000000000000000000087`, `hex`);

    public constructor(private aesKey: Buffer) {
        if (!(aesKey instanceof Buffer)) throw new Error(`The key must be provided as a Buffer.`);
        if (!(aesKey.length in this.algorithms)) throw INVALID_AES_KEY_SIZE;

        this.algorithm = this.algorithms[aesKey.length];
        this._subKeys = this._createSubKeys();
        this._aesKeyLength = aesKey.length;
    }

    private _createSubKeys(): ICMACSubKeys {
        const s = this.aes(Buffer.alloc(this.blockSize, 0));

        let k1 = Bitwise.bitShiftLeft(s);
        if (s[0] & 0x80) k1 = Bitwise.xor(k1, AesCmac.CONSTANT_R128);

        let k2 = Bitwise.bitShiftLeft(k1);
        if (k1[0] & 0x80) k2 = Bitwise.xor(k2, AesCmac.CONSTANT_R128);

        return { k1, k2 };
    }

    private getBlockCount(message: Buffer): number {
        const blockCount = Math.ceil(message.length / this.blockSize);
        return blockCount === 0 ? 1 : blockCount;
    }

    private aes(message: Buffer): Buffer {
        const z = Buffer.alloc(this.blockSize, 0);
        const cipher = createCipheriv(this.algorithm, this.aesKey, z);
        const result = cipher.update(message);
        cipher.final();
        return result;
    }

    private getLastBlock(message: Buffer, subKey?: Buffer): Buffer {

        const blockCount = this.getBlockCount(message);
        const paddedBlock = this.padding(message, blockCount - 1);

        let complete = false;
        if (message.length > 0) {
            complete = (message.length % this.blockSize) === 0;
        }

        const key = complete ? this.subKeys.k1 : this.subKeys.k2;
        return Bitwise.xor(paddedBlock, subKey || key);
    }

    private padding(message: Buffer, blockIndex: number): Buffer {
        const block = Buffer.alloc(this.blockSize, 0);

        const from = blockIndex * this.blockSize;
        const bytes = message.copy(block, 0, from);

        if (bytes !== this.blockSize) {
            block[bytes] = 0x80;
        }

        return block;
    }

    public calculate(message: Buffer, subKey?: Buffer): Buffer {
        if (!(message instanceof Buffer)) throw new Error(`The message must be provided as a Buffer.`);

        const blockCount = this.getBlockCount(message);

        let x = Buffer.alloc(this.blockSize, 0);
        let y = Buffer.alloc(0);

        for (let i = 0; i < blockCount - 1; i++) {
            const from = i * this.blockSize;
            const block = message.slice(from, from + this.blockSize);
            y = Bitwise.xor(x, block);
            x = this.aes(y);
        }

        y = Bitwise.xor(x, this.getLastBlock(message, subKey));
        x = this.aes(y);

        return x;
    }

    clear() {
        this._subKeys.k1.fill(0);
        this._subKeys.k2.fill(0);
    }

    public get subKeys(): ICMACSubKeys {
        return this._subKeys;
    }

    public get aesKeyLength(): number {
        return this._aesKeyLength;
    }
}
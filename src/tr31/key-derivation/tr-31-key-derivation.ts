import {INVALID_AES_KEY_SIZE, AesCmac} from "../../utils";

export enum KDID_COUNTER {
    FIRST = 0x01,
    SECOND = 0x02
}

export enum KDID_KEY_USAGE_INDICATOR {
    ENCRYPTION = 0x0000,
    MAC = 0x0001
}

export enum KDID_ALGORITHM_INDICATOR {
    AES_128 = 0x0002,
    AES_192 = 0x0003,
    AES_256 = 0x0004
}

export enum KDID_LENGTH {
    AES_128 = 0x0080,
    AES_192 = 0x00C0,
    AES_256 = 0x0100
}

export interface ITr31KeyDerivationInputOptions {
    keyUsageIndicator: KDID_KEY_USAGE_INDICATOR;
    aesCmac: AesCmac;
}

export class Tr31KeyDerivation {

    private readonly _aesCmac: AesCmac;
    private readonly _keyUsageIndicator: KDID_KEY_USAGE_INDICATOR;

    private static CMAC_PADDING = Buffer.from('8000000000000000', 'hex');
    private static SEPARATOR = 0x00;

    constructor(options: ITr31KeyDerivationInputOptions) {
        this._aesCmac = options.aesCmac;
        this._keyUsageIndicator = options.keyUsageIndicator;
    }

    public static build(options: ITr31KeyDerivationInputOptions): Tr31KeyDerivation {
        return new Tr31KeyDerivation(options);
    }

    private _getBlock(counter: KDID_COUNTER) {
        const _block = Buffer.alloc(8);
        _block.writeUInt8(counter);
        _block.writeUInt16BE(this.keyUsageIndicator,1);
        _block.writeUInt8(Tr31KeyDerivation.SEPARATOR, 3);
        _block.writeUInt16BE(this.algorithmIndicator, 4);
        _block.writeUInt16BE(this.length, 6);
        return Buffer.concat([
            _block, Tr31KeyDerivation.CMAC_PADDING
        ]);
    }

    private _getFirstBlock() {
        return this._getBlock(KDID_COUNTER.FIRST);
    }

    private _getSecondBlock() {
        return this._getBlock(KDID_COUNTER.SECOND);
    }

    public calculateCmac(): Buffer {
        if(!this.hasTwoBlocks) {
            return this._aesCmac.calculate(this._getFirstBlock(), this._aesCmac.subKeys.k2)
        } else {
            return Buffer.concat([
                this._aesCmac.calculate(this._getFirstBlock(), this._aesCmac.subKeys.k2),
                this._aesCmac.calculate(this._getSecondBlock(), this._aesCmac.subKeys.k2),
            ])
        }
    }

    get keyUsageIndicator(): KDID_KEY_USAGE_INDICATOR {
        return this._keyUsageIndicator;
    }

    get algorithmIndicator(): KDID_ALGORITHM_INDICATOR {
        switch (this._aesCmac.aesKeyLength) {
            case 16:
                return KDID_ALGORITHM_INDICATOR.AES_128;
            case 24:
                return KDID_ALGORITHM_INDICATOR.AES_192;
            case 32:
                return KDID_ALGORITHM_INDICATOR.AES_256;
            default:
                throw INVALID_AES_KEY_SIZE
        }
    }

    get length(): number {
        switch (this._aesCmac.aesKeyLength) {
            case 16:
                return KDID_LENGTH.AES_128;
            case 24:
                return KDID_LENGTH.AES_192;
            case 32:
                return KDID_LENGTH.AES_256;
            default:
                throw INVALID_AES_KEY_SIZE
        }
    }

    get hasTwoBlocks(): boolean {
        return this._aesCmac.aesKeyLength > 16;
    }
}
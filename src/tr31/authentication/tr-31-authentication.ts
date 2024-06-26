import {AesCmac, bufferToHex} from "../../utils";
import {KDID_KEY_USAGE_INDICATOR, Tr31KeyDerivation} from "../key-derivation";

export interface ITr31AuthenticationOptions {
    aesCmac: AesCmac;
}

export class Tr31Authentication {

    public static MAC_BLOCK_BYTE_LENGTH = 16;
    public static MAC_BLOCK_HEX_LENGTH = 32;
    public static MAC_BLOCK_BITS_LENGTH = 128;

    private readonly _keyBlockAuthenticationKey: Buffer;
    private readonly _aesCmac: AesCmac;

    private _macBuffer: Buffer = Buffer.alloc(16, 0);

    constructor(options: ITr31AuthenticationOptions, keyBlock?: string) {

        this._keyBlockAuthenticationKey = Tr31KeyDerivation.build({
            aesCmac: options.aesCmac,
            keyUsageIndicator: KDID_KEY_USAGE_INDICATOR.MAC
        }).calculateCmac();

        this._aesCmac = new AesCmac(this._keyBlockAuthenticationKey);

        if(keyBlock) this._macBuffer = Buffer.from(keyBlock.slice(keyBlock.length - 32), 'hex');
    }

    public static buildFromKeyBlock(keyBlock: string, options: ITr31AuthenticationOptions) {
        return new Tr31Authentication(options, keyBlock);
    }

    calculateMac(header: Buffer, data: Buffer): Tr31Authentication {
        this._macBuffer = this._aesCmac.calculate(Buffer.concat([header, data]));
        return this;
    }

    clear(): void {
        this._keyBlockAuthenticationKey.fill(0);
        this._aesCmac.clear();
    }

    public get buffer(): Buffer {
        return Buffer.from(this._macBuffer);
    }

    public get hex(): string {
        return bufferToHex(this._macBuffer);
    }
}
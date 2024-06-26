import {AesCmac} from "../utils";
import {Tr31Header} from "./header";
import {Tr31Authentication} from "./authentication";
import {Tr31Data} from "./data";

export interface Tr31ReaderOptions {
    keyBlockProtectionKey: Buffer;
    keyBlock: string;
}

export class Tr31Reader {

    private readonly _aesCmac: AesCmac;

    private readonly _keyBlock: string;
    private readonly _keyBlockHeader: Tr31Header;
    private readonly _keyBlockAuthentication: Tr31Authentication;
    private readonly _keyBlockData: Tr31Data;

    constructor(options: Tr31ReaderOptions) {
        if(options.keyBlock.length % 16) throw new Error(`Invalid Key Block size ${this._keyBlock.length} bytes. Must be multiple of 16.`);

        this._aesCmac = new AesCmac(options.keyBlockProtectionKey);

        this._keyBlock = options.keyBlock;

        this._keyBlockHeader = Tr31Header.buildFromKeyBlock(options.keyBlock);
        this._keyBlockAuthentication = Tr31Authentication.buildFromKeyBlock(options.keyBlock, {
            aesCmac: this._aesCmac
        });
        this._keyBlockData = Tr31Data.buildFromKeyBlock({
            aesCmac: this._aesCmac
        }, {
            keyBlock: options.keyBlock,
            mac: this._keyBlockAuthentication.buffer,
            keyBlockHeader: this._keyBlockHeader
        })

        this._aesCmac.clear();
    }

    public static build(options: Tr31ReaderOptions): Tr31Reader {
        return new Tr31Reader(options);
    }

    getHeader(): Tr31Header {
        return this._keyBlockHeader;
    }

    getData(): Tr31Data {
        return this._keyBlockData;
    }

    getAuthentication(): Tr31Authentication {
        return this._keyBlockAuthentication;
    }

    dispose(): void {
        this._keyBlockHeader.clear();
        this._keyBlockData.clear();
        this._keyBlockAuthentication.clear();
    }

}
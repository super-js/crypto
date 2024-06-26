import { Tr31Header } from "./header";
import { Tr31Data } from "./data";
import { Tr31Authentication } from "./authentication";
import {INVALID_SPECIFIC_AES_KEY_SIZE, AesCmac, bufferToHex} from "../utils";

export interface ITr31BuilderOptions {
    keyBlockProtectionKey: Buffer;
}

export interface ITr31FinalResult {
    header: string;
    data: string;
    mac: string;
    block: string;
}

export class Tr31Builder {

    private readonly _aesCmac: AesCmac;
    private readonly _data: Tr31Data;
    private readonly _authentication: Tr31Authentication;

    private _header: Tr31Header = new Tr31Header();

    constructor(options: ITr31BuilderOptions) {
        this._aesCmac = new AesCmac(options.keyBlockProtectionKey);

        this._data = new Tr31Data({
            aesCmac: this._aesCmac
        });

        this._authentication = new Tr31Authentication({
            aesCmac: this._aesCmac,
        });

        this._aesCmac.clear();
    }

    public static build(options: ITr31BuilderOptions): Tr31Builder {
        return new Tr31Builder(options);
    }

    private _setKeyBlockLength() {
        this._header.setKeyBlockLength(this._data.hexLength);
    }

    private _setHeaderPadding() {
        this._header.updatePadding();
        this._onHeaderOrDataAdded();
    }

    private _calculateAuthenticationMac() {
        this._authentication.calculateMac(this._header.buffer, this._data.buffer);
    }

    private _onHeaderOrDataAdded() {
        if(this._data.hasData) {
            this._calculateAuthenticationMac();
            this._setKeyBlockLength();
        }
    }

    public setHeader(header: Tr31Header): Tr31Builder {
        this._header = header;
        this._onHeaderOrDataAdded();
        return this;
    }

    public setData(data: string | Buffer): Tr31Builder {
        this._data.setData(data);
        this._data.setPadding(this._header.algorithm);
        this._onHeaderOrDataAdded();
        return this;
    }

    public final(): ITr31FinalResult {
        this._setHeaderPadding();
        const headerAscii = this._header.ascii;
        const macBuffer = this._authentication.buffer;
        const encryptedData = bufferToHex(this._data.encryptData(macBuffer));
        const mac = bufferToHex(macBuffer);

        this._header.clear();
        this._data.clear();
        this._authentication.clear();

        return {
            header: headerAscii,
            data: encryptedData,
            mac,
            block: `${headerAscii}${encryptedData}${mac}`
        }
    }

    public getHeader(): Tr31Header {
        return this._header;
    }

    public getData(): Tr31Data {
        return this._data;
    }

    public getAuthentication(): Tr31Authentication {
        return this._authentication;
    }

    get buffer(): Buffer {
        return Buffer.concat([
            this._header.buffer,
            this._data.buffer,
            this._authentication.buffer
        ])
    }

    public get asString(): string {
        return `${this._header.ascii}${this._data.buffer.toString('hex')}`
    }

}
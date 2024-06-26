import {OPTIONAL_BLOCK_ID, OptionalBlock} from "../optional-block";

export interface ITDEADuktptIdOptions {
    keySetId: string;
    deviceId: string;
}

export class TDEADuktptId extends OptionalBlock {

    constructor(options: ITDEADuktptIdOptions) {

        if(options.keySetId.length !== 10) throw new Error(`KEY SET ID must be exactly 10 characters long`);
        if(options.deviceId.length !== 5) throw new Error(`DEVICE ID must be exactly 5 characters long`);

        const deviceIdBuffer = Buffer.alloc(10, 0x30);
        deviceIdBuffer.write(options.deviceId, 'ascii');

        super({
            blockId: OPTIONAL_BLOCK_ID.TDEA_DUKPT_ID,
            data: Buffer.concat([
                Buffer.from(options.keySetId, 'ascii'),
                deviceIdBuffer
            ])
        });
    }
}
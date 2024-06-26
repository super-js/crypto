import {OPTIONAL_BLOCK_ID, OptionalBlock} from "../optional-block";

export enum BDKI_DUKPT_KEY_TYPE {
    TDES_KSI = 0x3030,
    AES_BDK_ID = 0x3031
}

enum BDKI_DUKPT_LENGTH {
    BDK_ID = 0x3045,
    KSI_ID = 0x3130
}

export interface IBdkiDukptOptions {
    keyType: BDKI_DUKPT_KEY_TYPE;
    content: string;
}

export class BdkiDukpt extends OptionalBlock {

    constructor(options: IBdkiDukptOptions) {

        if(options.keyType === BDKI_DUKPT_KEY_TYPE.TDES_KSI && options.content.length !== 10) throw new Error(`KSI must be exactly 10 characters`);
        if(options.keyType === BDKI_DUKPT_KEY_TYPE.AES_BDK_ID && options.content.length !== 8) throw new Error(`BDK ID must be exactly 8 characters`);

        const keyType = Buffer.alloc(2);
        keyType.writeUInt16BE(options.keyType);

        super({
            blockId: OPTIONAL_BLOCK_ID.BDKI_DUKPT,
            data: Buffer.concat([
                keyType,
                Buffer.from(options.content, 'ascii')
            ])
        });
    }
}
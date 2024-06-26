import {OPTIONAL_BLOCK_ID, OptionalBlock} from "../optional-block";

export enum ASYMMETRIC_KEY_LIFE {
    EPHEMERAL = 0x3030,
    PERMANENT = 0x3031
}

export interface IAsymmetricKeyLifeOptions {
    asymmetricKeyLife: ASYMMETRIC_KEY_LIFE;
}

export class AsymmetricKeyLife extends OptionalBlock {

    public static VERSION = 0x3031;

    constructor(options: IAsymmetricKeyLifeOptions) {

        const data = Buffer.alloc(4);
        data.writeUInt16BE(AsymmetricKeyLife.VERSION, 0);
        data.writeUInt16BE(options.asymmetricKeyLife, 2);

        super({
            blockId: OPTIONAL_BLOCK_ID.ASYMMETRIC_KEY_LIFE_ATTRIBUTE,
            data
        });
    }
}
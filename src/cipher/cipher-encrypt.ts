import {createCipheriv} from 'crypto';
import {CIPHER_ALGORITHM} from "./cipher-algorithms";

export interface ICipherEncryptOptions {
    key: Buffer;
    iv: Buffer;
    data: Buffer;
}

export class CipherEncrypt {

    private static _encrypt(algorithm: CIPHER_ALGORITHM, options: ICipherEncryptOptions): Buffer {
        const cipher = createCipheriv(algorithm, options.key, options.iv);
        cipher.setAutoPadding(false);
        const encrypted = cipher.update(options.data);
        return Buffer.concat([encrypted, cipher.final()]);
    }

    public static encryptWithAes128CBC(options: ICipherEncryptOptions): Buffer {
        return CipherEncrypt._encrypt(CIPHER_ALGORITHM.AES_128_CBC, options);
    }

    public static encryptWithAes192CBC(options: ICipherEncryptOptions): Buffer {
        return CipherEncrypt._encrypt(CIPHER_ALGORITHM.AES_192_CBC, options);
    }

    public static encryptWithAes256CBC(options: ICipherEncryptOptions): Buffer {
        return CipherEncrypt._encrypt(CIPHER_ALGORITHM.AES_256_CBC, options);
    }
}

import {createCipheriv, createDecipheriv} from 'crypto';
import {CIPHER_ALGORITHM} from "./cipher-algorithms";
import {ICipherEncryptOptions} from "./cipher-encrypt";

export interface ICipherDecryptOptions {
    key: Buffer;
    iv: Buffer;
    data: Buffer;
}

export class CipherDecrypt {

    private static _decrypt(algorithm: CIPHER_ALGORITHM, options: ICipherEncryptOptions): Buffer {
        const cipher = createDecipheriv(algorithm, options.key, options.iv);
        cipher.setAutoPadding(false);
        const decrypted = cipher.update(options.data);
        return Buffer.concat([
            decrypted, cipher.final()
        ])
    }

    public static decryptWithAes128CBC(options: ICipherEncryptOptions): Buffer {
        return CipherDecrypt._decrypt(CIPHER_ALGORITHM.AES_128_CBC, options);
    }

    public static decryptWithAes192CBC(options: ICipherEncryptOptions): Buffer {
        return CipherDecrypt._decrypt(CIPHER_ALGORITHM.AES_192_CBC, options);
    }

    public static decryptWithAes256CBC(options: ICipherEncryptOptions): Buffer {
        return CipherDecrypt._decrypt(CIPHER_ALGORITHM.AES_256_CBC, options);
    }
}

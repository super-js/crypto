export const KEY_BLOCK_HEADER_ALGORITHM_OFFSET = 7;

export enum KEY_BLOCK_HEADER_ALGORITHM {
    AES = 0x41, // AES
    DEA = 0x44, // DEA
    EC = 0x45, // EC
    HMAC = 0x48, // HMAC
    RSA = 0x52, // RSA
    DSA = 0x53, // DSA
    TDEA = 0x54 // TDEA
}

export type TKeyBlockHeaderAlgorithm = keyof typeof KEY_BLOCK_HEADER_ALGORITHM;
export enum KEY_BLOCK_HEADER_VERSION {
    'B' = 0x42, // Key Block protected using the TDEA Key Derivation Binding Method
    'C' = 0x43, // Key Block protected using the TDEA Key Variant Binding Method
    'D' = 0x44 // Key Block protected using the AES Key Derivation Binding Method
}

export const KEY_BLOCK_HEADER_VERSION_OFFSET = 0;

export type TKeyBlockHeaderVersion = keyof typeof KEY_BLOCK_HEADER_VERSION;
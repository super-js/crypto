export const KEY_BLOCK_HEADER_MODE_OFFSET = 8;

export enum KEY_BLOCK_HEADER_MODE_OF_USE {
    ALL = 0x42, // Both Encrypt/Wrap & Decrypt/Unwrap
    GENERATE_VERIFY = 0x43, // Both Generate & Verify
    DECRYPT_UNWRAP_ONLY = 0x44, // Decrypt/Unwrap Only
    ENCRYPT_WRAP_ONLY = 0x45, // Encrypt/Wrap Only
    GENERATE_ONLY = 0x47, // Generate Only
    NO_RESTRICTIONS = 0x4E, // No special restrictions
    SIGNATURE_ONLY = 0x53, // Signature Only
    SIGN_DECRYPT = 0x55, // Both Sign & Decrypt
    VERIFY_ONLY = 0x56, // Verify Only
    KEY_DERIVATION = 0x58, // Key used to derive other key(s)
    KEY_VARIATION = 0x59, // Key used to create key variant(s)
}

export type TKeyBlockHeaderModeOfUse = keyof typeof KEY_BLOCK_HEADER_MODE_OF_USE;
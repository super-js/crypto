export const KEY_BLOCK_HEADER_CONTEXT_OFFSET = 14;

export enum KEY_BLOCK_HEADER_CONTEXT {
    BOTH = 0x30,
    STORAGE = 0x31,
    EXCHANGE = 0x32
}

export type TKeyBlockHeaderKeyContext = keyof typeof KEY_BLOCK_HEADER_CONTEXT;
export const KEY_BLOCK_HEADER_KEY_EXPORTABILITY_OFFSET = 11;

export enum KEY_BLOCK_HEADER_EXPORTABILITY {
    EXPORTABLE = 0x45, // Exportable under a KEK in a form meeting the requirements of ANSI X9.24 Parts 1 or 2.
    NON_EXPORTABLE = 0x4E, // Non-exportable by the receiver of the Key Block, or from storage. Does not preclude exporting keys derived from a non-exportable key.
    SENSITIVE = 0x53 // Sensitive, Exportable under a KEK in a form not necessarily meeting the requirements of ANSI X9.24 Parts 1 or 2.
}

export type TKeyBlockHeaderExportability = keyof typeof KEY_BLOCK_HEADER_EXPORTABILITY;
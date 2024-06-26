export const INVALID_AES_KEY_SIZE = new Error('AES Key size must be 128, 192, or 256 bits.');
export const INVALID_SPECIFIC_AES_KEY_SIZE = (noOfBits: number) => new Error(`Only AES key of size ${noOfBits} bits is currently supported.`);
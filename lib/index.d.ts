export interface options {
  saltBits: number;
  salt?: string;
  algorithm: string;
  iterations: number;
  iv?: string;
  minPasswordlength: number;
}

export interface defaultObjects {
  saltBits: number;
  algorithm: string;
  iterations: number;
  minPasswordlength: number;
}

export interface defaults {
  encryption: defaultObjects;
  integrity: defaultObjects;
  ttl: number;
  timestampSkewSec: number;
  localtimeOffsetMsec: number;
}

/**
 * Generates a key from the password
 * 
 * @param password - A password string or buffer key
 * @param options - Object used to customize the key derivation algorithm
 * 
 * @returns An object with keys: key, salt, iv
 */

export function generateKey(password: string | Buffer, options: options): {key: string, salt: string, iv: string}


/**
* Encrypt data
* 
* @param password - A password string or buffer key
* @param options - Object used to customize the key derivation algorithm
* @param data - String to encrypt
* 
* @returns an object with the following keys: encrypted, key
*/

export function encrypt(password: string | Buffer, options: options, data: string): { encrypted: Buffer, key: { key: string, salt: string, iv: string }}


/**
* Decrypt data
* 
* @param password - A password string or buffer key
* @param options - Object used to customize the key derivation algorithm
* @param data - String to decrypt
* 
* @returns the decrypted string
*/

export function decrypt(password: string | Buffer, options: options, data: string): string


/**
* Calculates a HMAC digest
* 
* @param password - A password string or buffer key
* @param options - Object used to customize the key derivation algorithm
* @param data - String to calculate the HMAC over
* 
* @returns An object with the following keys: digest, salt
*/

export function hmacWithPassword(password: string | Buffer, options: options, data: string): { digest: string, salt: string }


/**
* Serializes, encrypts, and signs objects into an iron protocol string
* 
* @param object - Data being sealed
* @param password - A string, buffer, or object
* @param options - Object used to customize the key derivation algorithm
* 
* @returns Iron sealed string
*/

export function seal(object: any, password: string | Buffer | {id: string, secret: string} | {id: string, encryption: string, integrity: string}, options: defaults): string


/**
* Verifies, decrypts, and reconstruct an iron protocol string into an object
* 
* @param sealed - The iron protocol string generated with seal()
* @param password - A string, buffer, or object
* @param options - Object used to customize the key derivation algorithm
* 
* @returns the verified decrypted object
*/

export function unseal(sealed: string, password: string | Buffer | {id: string | Buffer | {encryption: string, integrity: string}}, options: defaults): object


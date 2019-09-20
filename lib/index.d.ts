export interface Options {
    saltBits: number;
    salt?: string;
    algorithm: string;
    iterations: number;
    iv?: string;
    minPasswordlength: number;
}


export interface DefaultObjects {
    saltBits: number;
    algorithm: string;
    iterations: number;
    minPasswordlength: number;
}


export interface Defaults {
    encryption: DefaultObjects;
    integrity: DefaultObjects;
    ttl: number;
    timestampSkewSec: number;
    localtimeOffsetMsec: number;
}


export interface Key {
    key: string;
    salt: string;
    iv: string;
}


type Password = string | Buffer


declare namespace password {

    interface Secret {
        id?: string,
        secret: Password
    }

    interface Specific {
        id?: string,
        encryption: Password,
        integrity: Password
    }

    interface Hash {
        [id: string]: Password | Secret | Specific;
    }
}


/**
Generates a key from the password

@param password - A password string or buffer key
@param options - Object used to customize the key derivation algorithm

@returns An object with keys: key, salt, iv
*/

export function generateKey(password: Password, options: Options): Key


/**
Encrypt data

@param password - A password string or buffer key
@param options - Object used to customize the key derivation algorithm
@param data - String to encrypt

@returns an object with the following keys: encrypted, key
*/

export function encrypt(password: Password, options: Options, data: string): { encrypted: Buffer, key: Key }


/**
Decrypt data

@param password - A password string or buffer key
@param options - Object used to customize the key derivation algorithm
@param data - String to decrypt

@returns the decrypted string
*/

export function decrypt(password: Password, options: Options, data: string): string


/**
Calculates a HMAC digest

@param password - A password string or buffer key
@param options - Object used to customize the key derivation algorithm
@param data - String to calculate the HMAC over

@returns An object with the following keys: digest, salt
*/

export function hmacWithPassword(password: Password, options: Options, data: string): { digest: string, salt: string }


/**
Serializes, encrypts, and signs objects into an iron protocol string

@param object - Data being sealed
@param password - A string, buffer, or object
@param options - Object used to customize the key derivation algorithm

@returns Iron sealed string
*/

export function seal(object: any, password: Password | password.Secret | password.Specific, options: Defaults): string


/**
Verifies, decrypts, and reconstruct an iron protocol string into an object

@param sealed - The iron protocol string generated with seal()
@param password - A string, buffer, or object
@param options - Object used to customize the key derivation algorithm

@returns the verified decrypted object
*/

export function unseal(sealed: string, password: Password | password.Hash, options?: Defaults): object

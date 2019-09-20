/**
Configuration options for built-in algorithms.
*/
export interface Algorithms {
    'aes-128-ctr': {
        keyBits: number;
        ivBits: number;
    };

    'aes-256-cbc': {
        keyBits: number;
        ivBits: number;
    };

    'sha256': {
        keyBits: number;
    };
}


/**
seal() method options.
*/
export interface SealOptionsSub {

    /**
    The length of the salt (random buffer used to ensure that two identical objects will generate a different encrypted result). Defaults to 256.
    */
    saltBits: number;

    /**
    The algorithm used. Defaults to 'aes-256-cbc' for encryption and 'sha256' for integrity.
    */
    algorithm: keyof Algorithms;

    /**
    The number of iterations used to derive a key from the password. Defaults to 1.
    */
    iterations: number;

    /**
    Minimum password size. Defaults to 32.
    */
    minPasswordlength: number;
}


/**
generateKey() method options.
*/
export interface GenerateKeyOptions extends Pick<SealOptionsSub, 'algorithm' | 'iterations' | 'minPasswordlength'> {

    saltBits?: number;
    salt?: string;
    iv?: string;
}


/**
Options for customizing the key derivation algorithm used to generate encryption and integrity verification keys as well as the algorithms and salt sizes used.
*/
export interface SealOptions {

    /**
    Encryption step options.
    */
    encryption: SealOptionsSub;

    /**
    Integrity step options.
    */
    integrity: SealOptionsSub;

    /**
    Sealed object lifetime in milliseconds where 0 means forever. Defaults to 0.
     */
    ttl: number;

    /**
    Number of seconds of permitted clock skew for incoming expirations. Defaults to 60 seconds.
    */
    timestampSkewSec: number;

    /**
    Local clock time offset, expressed in number of milliseconds (positive or negative). Defaults to 0.
    */
    localtimeOffsetMsec: number;
}


/**
Generated internal key object.
*/
export interface Key {
    key: Buffer;
    salt: string;
    iv: string;
}


/**
Generated HMAC internal results.
*/
export interface HMacResult {
    digest: string;
    salt: string;
}


/**
Password secret string or buffer.
*/
type Password = string | Buffer


declare namespace password {

    /**
    Secret object with optional id.
    */
    interface Secret {
        id?: string,
        secret: Password
    }

    /**
    Secret object with optional id and specified password for each encryption and integrity.
    */
    interface Specific {
        id?: string,
        encryption: Password,
        integrity: Password
    }

    /**
    Key-value pairs hash of password id to value
    */
    interface Hash {
        [id: string]: Password | Secret | Specific;
    }
}


/**
The default encryption and integrity settings.
*/
export const defaults: SealOptions;


/**
Configuration of each supported algorithm. 
*/
export const algorithms: Algorithms;


/**
MAC normalization format version.
*/
export const macFormatVersion: string;


/**
MAC normalization prefix.
*/
export const macPrefix: string;


/**
Generates a key from the password

@param password - A password string or buffer key
@param options - Object used to customize the key derivation algorithm

@returns An object with keys: key, salt, iv
*/
export function generateKey(password: Password, options: GenerateKeyOptions): Promise<Key>


/**
Encrypt data

@param password - A password string or buffer key
@param options - Object used to customize the key derivation algorithm
@param data - String to encrypt

@returns an object with the following keys: encrypted, key
*/
export function encrypt(password: Password, options: GenerateKeyOptions, data: string): Promise<{ encrypted: Buffer, key: Key }>


/**
Decrypt data

@param password - A password string or buffer key
@param options - Object used to customize the key derivation algorithm
@param data - String to decrypt

@returns the decrypted string
*/
export function decrypt(password: Password, options: GenerateKeyOptions, data: string): Promise<string>


/**
Calculates a HMAC digest

@param password - A password string or buffer key
@param options - Object used to customize the key derivation algorithm
@param data - String to calculate the HMAC over

@returns An object with the following keys: digest, salt
*/
export function hmacWithPassword(password: Password, options: GenerateKeyOptions, data: string): Promise<HMacResult>


/**
Serializes, encrypts, and signs objects into an iron protocol string

@param object - Data being sealed
@param password - A string, buffer, or object
@param options - Object used to customize the key derivation algorithm

@returns Iron sealed string
*/
export function seal(object: any, password: Password | password.Secret | password.Specific, options: SealOptions): Promise<string>


/**
Verifies, decrypts, and reconstruct an iron protocol string into an object

@param sealed - The iron protocol string generated with seal()
@param password - A string, buffer, or object
@param options - Object used to customize the key derivation algorithm

@returns the verified decrypted object
*/
export function unseal(sealed: string, password: Password | password.Hash, options?: SealOptions): Promise<any>

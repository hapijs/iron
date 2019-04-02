# v5.1.x API Reference

<!-- toc -->

- [Methods](#methods)
  - [`await seal(object, password, options)`](#await-sealobject-password-options)
  - [`await unseal(sealed, password, options)`](#await-unsealsealed-password-options)
  - [`await generateKey(password, options)`](#await-generatekeypassword-options)
  - [`await encrypt(password, options, data)`](#await-encryptpassword-options-data)
  - [`await decrypt(password, options, data)`](#await-decryptpassword-options-data)
  - [`await hmacWithPassword(password, options, data)`](#await-hmacwithpasswordpassword-options-data)
- [Options](#options)
  - [Defaults](#defaults)

<!-- tocstop -->

## Methods

### `await seal(object, password, options)`

Seriealizes, encrypts, and signs objects into an **iron** protocol string where:

- `object` - the data being sealed. Can be any JavaScript value that is serializable via
  `JSON.stringify()`.

- `password` - one of:

    - a password string used to generate a key using the pbkdf2 algorithm.

    - a key buffer used as-is (after validating sufficient length based on the algorithm used).

    - an object with:
        - `id` - a password identifier (must consist of only letters, numbers, and `_`).
        - `secret` - a password string or key buffer used for both encryption and integrity.
    
    - an object with:
        - `id` - a password identifier (must consist of only letters, numbers, and `_`).
        - `encryption` - a password string or key buffer used for encryption.
        - `integrity` - a password string or key buffer used for integrity.

- `options` - see [Options](#options).

Return value: **iron** sealed string.

Note: assigning the password used an `id` allows for password rotation to improve the security of
your deployment. Passwords should be rotated over time to reduce the risk of compromised security.
When providing a password id, the id is included with the **iron** protocol string and it must
match the id used to unseal.

It is recommended to combine password id with the `ttl` option to generate **iron** protocol
strings of limited time validity which also allow for rotating passwords without the need to keep
all previous passwords around (only the number of passwords used within the ttl window).

### `await unseal(sealed, password, options)`

Verifies, decrypts, and reconstruct an **iron** protocol string into an object where:

- `sealed` - the **iron** protocol string generated with [`seal()`](#await-sealobject-password-options).

- `password` - must match the `password` value passed to [`seal()`](#await-sealobject-password-options)
  and be one of:

    - a password string used to generate a key using the pbkdf2 algorithm.

    - a key buffer used as-is (after validating sufficient length based on the algorithm used).

    - an object with `id` as the key and value is one of:
        - a password string or key buffer used for both encryption and integrity.
        - an object with:
            - `encryption` - a password string or key buffer used for encryption.
            - `integrity` - a password string or key buffer used for integrity.

- `options` - see [Options](#options). Must match the `options` value passed to
  [`seal()`](#await-sealobject-password-options)

Return value: the verified, decripted object.

Note: In order to enable password rotation, the `password` argument can accept an object with more
than one password, each keyed by its id. Together with the `ttl` option, the `password` object only
needs to include the passwords used within the ttl window.

### `await generateKey(password, options)`

Generates an key from the password where:
- `password` - a password string or buffer key.
- `options` - see [Options](#options).

Return value: an object with the following keys:
- `key`
- `salt`
- `iv`

### `await encrypt(password, options, data)`

Encrypts data where:
- `password` - a password string or buffer key.
- `options` - see [Options](#options).
- 'data' - the string to encrypt.

Return value: an object with the following keys:
- `encrypted`
- `key`:
    - `key`
    - `salt`
    - `iv`

### `await decrypt(password, options, data)`

Decrypts data where:
- `password` - a password string or buffer key.
- `options` - see [Options](#options).
- 'data' - the string to decrypt.

Return value: the decrypted string.

### `await hmacWithPassword(password, options, data)`

Calculates an HMAC digest where:
- `password` - a password string or buffer key.
- `options` - see [Options](#options).
- 'data' - the string to calculate the HMAC over.

Return value: an object with the following keys:
- `digest`
- `salt`

## Options

**iron** provides options for customizing the key deriviation algorithm used to generate encryption
and integrity verification keys, as well as the algorithms and salt sizes used.**iron** methods
take an options object with the following keys:

- `encryption` - (required) defines the options used by the encryption process.
- `integrity` - (required) defines the options used by the HMAC integrity verification process.

Each of these option objects support the following keys:

- `algorithm` - (required) the algorithm name ('aes-256-cbc' and 'aes-128-ctr' for encryption and
  'sha256' for integrity are the only two supported at this time).
- `iv` - (optional) an [initialization vector](http://en.wikipedia.org/wiki/Initialization_vector)
  buffer. If no `iv` is provided, one is generated based on the algorithm `ivBits` configuration.

When the `password` argument passed is a string (used for key generation), the following options
are used:

- `salt` - (optional) a pre-generated salt string (a random buffer used to ensure that two
  identical objects will generate a different encrypted result).
- `saltBits` - (required if `salt` is not provided, otherwise ignored) the size of the salt.
- `iterations` - (required) the number of iterations used to derive a key from the password.
  Defaults to `1` iteration. The number of ideal iterations to use is dependent on your
  application's performance requirements. More iterations means it takes longer to generate the
  key.
- `minPasswordlength` - (required) the minimum password string length required for key generation.
  Defaults to `32` characters.

The _'seal()'_ and _'unseal()'_ methods also support the following options:

- `ttl` - sealed object lifetime in milliseconds where 0 means forever. Defaults to `0`.
- `timestampSkewSec` - number of seconds of permitted clock skew for incoming expirations.
  Defaults to `60` seconds.
- `localtimeOffsetMsec` - local clock time offset, expressed in number of milliseconds (positive or
  negative). Defaults to `0`.

### Defaults

**iron** includes a default options object which can be passed to the methods as shown above in the
example. The default settings are:

```javascript
var options = {
    encryption: {
        saltBits: 256,
        algorithm: 'aes-256-cbc',
        iterations: 1
    },
    integrity: {
        saltBits: 256,
        algorithm: 'sha256',
        iterations: 1
    },
    ttl: 0,
    timestampSkewSec: 60,
    localtimeOffsetMsec: 0
};
```

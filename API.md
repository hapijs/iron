
## Introduction

**iron** is a cryptographic utility for sealing a JSON object using symmetric key encryption with message
integrity verification. Or in other words, it lets you encrypt an object, send it around (in
cookies, authentication credentials, etc.), then receive it back and decrypt it. The algorithm
ensures that the message was not tampered with, and also provides a simple mechanism for password
rotation.

Note: the wire protocol has not changed since 1.x (the version increments reflected a change in
the internal error format used by the module and by the node API as well as other node API changes).

**iron** provides methods for encrypting an object, generating a message authentication code (MAC),
and serializing both into a cookie / URI / HTTP header friendly format. Sealed objects are useful
in cases where state has to reside on other applications not under your control, without exposing
the details of this state to those application.

For example, sealed objects allow you to encrypt the permissions granted to the authenticated user,
store those permissions using a cookie, without worrying about someone modifying (or even knowing)
what those permissions are. Any modification to the encrypted data will invalidate its integrity.

The seal process follows these general steps:

- generate encryption salt `saltE`
- derive an encryption key `keyE` using `saltE` and a password
- generate an integrity salt `saltI`
- derive an integrity (HMAC) key `keyI` using `saltI` and the password
- generate a random [initialization vector](http://en.wikipedia.org/wiki/Initialization_vector) `iv`
- encrypt the serialized object string using `keyE` and `iv`
- mac the encrypted object along with `saltE` and `iv`
- concatenate `saltE`, `saltI`, `iv`, and the encrypted object into a URI-friendly string

## Example

To seal an object:

```javascript
const obj = {
    a: 1,
    b: 2,
    c: [3, 4, 5],
    d: {
        e: 'f'
    }
};

const password = 'some_not_random_password_that_is_at_least_32_characters';

try {
    const sealed = await Iron.seal(obj, password, Iron.defaults);
} catch (err) {
    console.log(err.message);
}
```

The result `sealed` object is a string which can be sent via cookies, URI query parameter, or an
HTTP header attribute. To unseal the string:

```javascript
try {
    const unsealed = await Iron.unseal(sealed, password, Iron.defaults);
} catch (err) {
    console.log(err.message);
}
```

## Security Considerations

The greatest sources of security risks are usually found not in **iron** but in the policies and
procedures surrounding its use. Implementers are strongly encouraged to assess how this module
addresses their security requirements. This section includes an incomplete list of security
considerations that must be reviewed and understood before using **iron**.

### Plaintext Storage of Credentials

The **iron** password is only used to derive keys and is never sent or shared. However, in order to
generate (and regenerate) the keys used to encrypt the object and compute the request MAC, the
server must have access to the password in plaintext form. This is in contrast, for example, to
modern operating systems, which store only a one-way hash of user credentials.

If an attacker were to gain access to the password - or worse, to the server's database of all such
password - he or she would be able to encrypt and decrypt any sealed object. Accordingly, it is
critical that servers protect these passwords from unauthorized access.

## Frequently Asked Questions

### Where is the protocol specification?

If you are looking for some prose explaining how all this works, there isn't any. **iron** is being
developed as an open source project instead of a standard. In other words, the [code](/lib) is the
specification. Not sure about something? Open an issue!

### Is it done?

Yep.

### How come the defaults must be manually passed and not automatically applied?

Because you should know what you are doing and explicitly set it. The options matter a lot to the
security properties of the implementation. While reasonable defaults are provided, you still need
to explicitly state you want to use them.

## Acknowledgements

Special thanks to Adam Barth for his infinite patience, and always insightful feedback and advice.

## Methods

### `await seal(object, password, options)`

Seriealizes, encrypts, and signs objects into an **iron** protocol string where:

- `object` - the data being sealed. Can be any JavaScript value that is serializable via
  `JSON.stringify()`. **Note**: `JSON.stringify` will not keep object properties which values are `undefined`. So if you pass an object like `{id: undefined}` then it will be serialized as `{}`.

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

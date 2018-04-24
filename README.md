# iron

<img align="right" src="https://raw.github.com/hueniverse/iron/master/images/logo.png" /> **iron**
is a cryptographic utility for sealing a JSON object using symmetric key encryption with message
integrity verification. Or in other words, it lets you encrypt an object, send it around (in
cookies, authentication credentials, etc.), then receive it back and decrypt it. The algorithm
ensures that the message was not tampered with, and also provides a simple mechanism for password
rotation.

Current version: **5.x**

Note: the wire protocol has not changed since 1.x (the version increments reflected a change in
the internal error format used by the module and by the node API as well as other node API changes).

[![Build Status](https://secure.travis-ci.org/hueniverse/iron.png)](http://travis-ci.org/hueniverse/iron)


## Table of Content

- [**Introduction**](#introduction)
<br /><br />
- [Usage](#usage)
<br /><br />
- [API](#api)
<br /><br />
- [**Security Considerations**](#security-considerations)
  - [Plaintext Storage of Credentials](#plaintext-storage-of-credentials)
<br /><br />
- [**Frequently Asked Questions**](#frequently-asked-questions)
<br /><br />
- [**Acknowledgements**](#acknowledgements)

## Introduction

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

## Usage

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

## API

See the detailed [API Reference](https://github.com/hueniverse/iron/blob/master/API.md).

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

The **iron** logo was based on original artwork created by [Chris Carrasco](http://chriscarrasco.com).

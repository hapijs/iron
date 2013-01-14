![iron](https://raw.github.com/hueniverse/iron/master/images/iron.png)

<img align="right" src="https://raw.github.com/hueniverse/iron/master/images/logo.png" /> **iron** is a cryptographic
utility for sealing a JSON object using symmetric key encryption with message integrity verification. Or in other words,
it lets you encrypt an object, send it around (in cookies, authentication credentials, etc.), then receive it back and
decrypt it. The algorithm ensures that the message was not tempered with, and also provides a simple mechanism for
password rotation.

Current version: **0.0.1**

[![Build Status](https://secure.travis-ci.org/hueniverse/iron.png)](http://travis-ci.org/hueniverse/iron)


# Table of Content

- [**Introduction**](#introduction)
<p></p>
- [Usage](#usage)
  - [Options](#options)
  - [Password Rotation](#password-rotation)
  - [Protocol Example](#protocol-example)
<p></p>
- [**Security Considerations**](#security-considerations)
  - [Plaintext Storage of Credentials](#plaintext-storage-of-credentials)
<p></p>
- [**Frequently Asked Questions**](#frequently-asked-questions)
<p></p>
- [**Acknowledgements**](#acknowledgements)

# Introduction

**iron** provides methods for encrypting an object, generating a massage authentication code (MAC), and serializing both
into a cookie / URI / HTTP header friendly format. Sealed objects are useful in cases where state has to reside on other
applications not under your control, without exposing the details of this state to those application.

For example, sealed objects allow you to encrypt the permissions granted to the authenticated user, store those permissions
using a cookie, without worrying about someone modifying (or even knowing) what those permissions are. Any modification to
the encrypted data will invalidate its integrity.


# Usage

To seal an object:

```javascript
var obj = {
    a: 1,
    b: 2,
    c: [3, 4, 5],
    d: {
        e: 'f'
    }
};

var password = 'some_not_random_password';

Iron.seal(obj, password, Iron.defaults, function (err, sealed) {

    console.log(sealed);
});
```

The result `sealed` object is a string which can be sent via cookies, URI query parameter, or an HTTP header attribute.
To unseal the string:

```javascript
Iron.unseal(sealed, password, Iron.defaults, function (err, unsealed) {

    // unsealed has the same content as obj
});
```

### Options


### Password Rotation



## Protocol Example


# Security Considerations

The greatest sources of security risks are usually found not in **iron** but in the policies and procedures surrounding its use.
Implementers are strongly encouraged to assess how this module addresses their security requirements. This section includes
an incomplete list of security considerations that must be reviewed and understood before using **iron**.


### Plaintext Storage of Credentials

The **iron** password is only used to derive keys and is never sent or shared. However, in order to generate (and regenerate) the
keys used to encrypt the object and compute the request MAC, the server must have access to the password in plaintext form. This
is in contrast, for example, to modern operating systems, which store only a one-way hash of user credentials.

If an attacker were to gain access to the password - or worse, to the server's database of all such password - he or she would be able
to encrypt and decrypt any sealed object. Accordingly, it is critical that servers protect these passwords from unauthorized
access.


# Frequently Asked Questions

### Where is the protocol specification?

If you are looking for some prose explaining how all this works, there isn't any. **iron** is being developed as an open source
project instead of a standard. In other words, the [code](/hueniverse/iron/tree/master/lib) is the specification. Not sure about
something? Open an issue!


### Is it done?

No but it's close. Until this module reaches version 1.0.0 it is considered experimental and is likely to change. This also
means your feedback and contribution are very welcome. Feel free to open issues with questions and suggestions.


# Acknowledgements

Special thanks to Adam Barth for his infinite patiace, and always insightful feedback and advice.

The **iron** logo was based on origin artwork created by [Chris Carrasco](http://chriscarrasco.com).

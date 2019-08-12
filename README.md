# iron

[![Build Status](https://travis-ci.org/hapijs/iron.svg?branch=v4-commercial)](https://travis-ci.org/hapijs/iron)

## License

This version of the package requires a commercial license. You may not use, copy, or distribute it without first acquiring a commercial license from Sideway Inc. Using this software without a license is a violation of US and international law. To obtain a license, please contact [sales@sideway.com](mailto:sales@sideway.com). The open source version of this package can be found [here](https://github.com/hapijs/iron).

## About

**iron** is a cryptographic utility for sealing a JSON object using symmetric key encryption with message integrity verification. Or in other words,
it lets you encrypt an object, send it around (in cookies, authentication credentials, etc.), then receive it back and
decrypt it. The algorithm ensures that the message was not tampered with, and also provides a simple mechanism for
password rotation.

Current version: **4.x**

Note: the wire protocol has not changed since 1.x (the version increments reflected a change in
the internal error format used by the module and by the node API as well as other node API changes).

[![Build Status](https://secure.travis-ci.org/hueniverse/iron.png)](http://travis-ci.org/hueniverse/iron)

## Documentation

[**API Reference**](API.md)

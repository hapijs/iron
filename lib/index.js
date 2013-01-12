// Load modules

var Crypto = require('crypto');
var Boom = require('boom');
var Hoek = require('hoek');


// Declare internals

var internals = {};


// Common defaults

exports.defaults = {
    encryptionKey: {
        saltBits: 256,
        algorithm: 'aes-256-cbc',
        iterations: 1
    },
    integrityKey: {
        saltBits: 256,
        algorithm: 'sha256',
        iterations: 1
    }
};


// Algorithm configuration

internals.algorithms = {

    'aes-128-ctr': { keyBits: 128, ivBits: 128 },       // Requires node 0.10.x
    'aes-256-cbc': { keyBits: 256, ivBits: 128 },
    'sha256': { keyBits: 256 }
};


// Generate a  cryptographically strong pseudo-random data

exports.randomBits = function (bits, callback) {

    var bytes = Math.ceil(bits / 8);
    Crypto.randomBytes(bytes, function (err, buffer) {

        if (err) {
            return callback(err);
        }

        return callback(null, buffer);
    });
};


// Generate a unique encryption key

/*
    var options =  {
        saltBits: 256,                                  // Ignored if salt is set
        salt: '4d8nr9q384nr9q384nr93q8nruq9348run',
        algorithm: 'aes-128-ctr',
        iterations: 1,
        iv: 'sdfsdfsdfsdfscdrgercgesrcgsercg'           // Optional
    };
*/

exports.generateKey = function (password, options, callback) {

    if (!password) {
        return callback(Boom.internal('Empty password'));
    }

    if (!options ||
        typeof options !== 'object') {

        return callback(Boom.internal('Bad options'));
    }

    var algorithm = internals.algorithms[options.algorithm];
    if (!algorithm) {
        return callback(Boom.internal('Unknown algorithm: ' + options.algorithm));
    }

    var generate = function () {

        if (options.salt) {
            generateKey(options.salt);
        }
        else if (options.saltBits) {
            generateSalt();
        }
        else {
            return callback(Boom.internal('Missing salt or saltBits options'));
        }
    };

    var generateSalt = function () {

        exports.randomBits(options.saltBits, function (err, randomSalt) {

            if (err) {
                return callback(err);
            }

            var salt = randomSalt.toString('hex');
            generateKey(salt);
        });
    };

    var generateKey = function (salt) {

        Crypto.pbkdf2(password, salt, options.iterations, algorithm.keyBits / 8, function (err, derivedKey) {

            if (err) {
                return callback(err);
            }

            var result = {
                key: derivedKey,
                salt: salt
            };

            if (algorithm.ivBits &&
                !options.iv) {

                exports.randomBits(algorithm.ivBits, function (err, randomIv) {

                    if (err) {
                        return callback(err);
                    }

                    result.iv = randomIv.toString('binary');
                    return callback(null, result);
                });
            }
            else {
                if (options.iv) {
                    result.iv = options.iv;
                }
                return callback(null, result);
            }
        });
    };

    generate();
};


// Encrypt data
// options: see exports.generateKey()

exports.encrypt = function (password, options, data, callback) {

    exports.generateKey(password, options, function (err, key) {

        if (err) {
            return callback(err);
        }

        var cipher = Crypto.createCipheriv(options.algorithm, key.key, key.iv);
        var enc = cipher.update(data, 'utf8', 'binary');
        enc += cipher.final('binary');

        callback(null, enc, key);
    });
};


// Decrypt data
// options: see exports.generateKey()

exports.decrypt = function (password, options, data, callback) {

    exports.generateKey(password, options, function (err, key) {

        if (err) {
            return callback(err);
        }

        var decipher = Crypto.createDecipheriv(options.algorithm, key.key, key.iv);
        var dec = decipher.update(data, 'binary', 'utf8');
        dec += decipher.final('utf8');

        callback(null, dec);
    });
};


// HMAC using a password
// options: see exports.generateKey()

exports.hmacWithPassword = function (password, options, data, callback) {

    exports.generateKey(password, options, function (err, key) {

        if (err) {
            return callback(err);
        }

        var hmac = Crypto.createHmac(options.algorithm, key.key).update(data);
        var digest = hmac.digest('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/\=/g, '');

        var result = {
            digest: digest,
            salt: key.salt
        };

        return callback(null, result);
    });
};


// Encrypt and HMAC an object
// options: see exports.defaults

exports.seal = function (object, encryptionPassword, options, callback) {

    var objectString = JSON.stringify(object);

    exports.encrypt(encryptionPassword, options.encryptionKey, objectString, function (err, encrypted, key) {

        if (err) {
            return callback(err);
        }

        // Base64url the encrypted value

        var encryptedB64 = Hoek.base64urlEncode(encrypted);
        var iv = Hoek.base64urlEncode(key.iv);
        var macBaseString = key.salt + ':' + iv + ':' + encryptedB64;

        // Mac the combined values

        var hmac = exports.hmacWithPassword(encryptionPassword, options.integrityKey, macBaseString, function (err, mac) {

            if (err) {
                return callback(err);
            }

            // Put it all together

            var sealed = mac.salt + ':' + mac.digest + ':' + macBaseString;        // hmac-salt:hmac:encryption-salt:encryption-iv:encrypted
            return callback(null, sealed);
        });
    });
};


// Decrypt and validate sealed string
// options: see exports.defaults

exports.unseal = function (sealed, encryptionPassword, options, callback) {

    // Break string into components

    var parts = sealed.split(':');
    if (parts.length !== 5) {
        return callback(Boom.internal('Incorrect number of sealed components'));
    }

    var hmacSalt = parts[0];
    var hmac = parts[1];
    var encryptionSalt = parts[2];
    var encryptionIv = parts[3];
    var encryptedB64 = parts[4];
    var macBaseString = encryptionSalt + ':' + encryptionIv + ':' + encryptedB64;

    // Check hmac

    var macOptions = Hoek.clone(options.integrityKey);
    macOptions.salt = hmacSalt;

    exports.hmacWithPassword(encryptionPassword, macOptions, macBaseString, function (err, mac) {

        if (err) {
            return callback(err);
        }

        if (hmac !== mac.digest) {
            return callback(Boom.internal('Bad hmac value'));
        }

        // Decrypt

        var encrypted = Hoek.base64urlDecode(encryptedB64);

        if (encrypted instanceof Error) {
            return callback(encrypted);
        }

        var decryptOptions = Hoek.clone(options.encryptionKey);
        decryptOptions.salt = encryptionSalt;
        decryptOptions.iv = Hoek.base64urlDecode(encryptionIv);

        exports.decrypt(encryptionPassword, decryptOptions, encrypted, function (err, decrypted) {

            // Parse JSON

            var object = null;
            try {
                object = JSON.parse(decrypted);
            }
            catch (err) {
                return callback(Boom.internal('Failed parsing sealed object JSON: ' + err.message));
            }

            return callback(null, object);
        });
    });
};


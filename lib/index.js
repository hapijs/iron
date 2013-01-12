// Load modules

var Utils = require('./utils');
var Crypto = require('./crypto');
var Settings = require('./settings');
var Err = require('./error');


// Declare internals

var internals = {};


// Export modules

exports.utils = Utils;
exports.crypto = Crypto;
exports.error = Err;
exports.settings = Settings;


exports.generate = function (envelope, encryptionPassword, callback) {

    // Generate ticket secret

    Crypto.randomBits(Settings.ticket.secretBits, function (err, random) {

        if (err) {
            return callback(err);
        }

        envelope.key = random.toString('hex');
        envelope.algorithm = Settings.ticket.hmacAlgorithm;

        // Seal envelope

        Crypto.seal(envelope, encryptionPassword, Settings.ticket, function (err, sealed) {

            if (err) {
                return callback(err);
            }

            envelope.id = sealed;

            // Hide private ext data

            if (envelope.ext &&
                typeof envelope.ext === 'object' &&
                envelope.ext.private) {

                delete envelope.ext.private;
            }

            return callback(null, envelope);
        });
    });
};


// Parse ticket id

exports.parse = function (id, encryptionPassword, callback) {

    Utils.toss(encryptionPassword, Err.internal('Invalid encryption password'), callback);

    Crypto.unseal(id, encryptionPassword, Settings.ticket, function (err, object) {

        if (err) {
            return callback(err);
        }

        var ticket = object;
        ticket.id = id;
        return callback(null, ticket);
    });
};


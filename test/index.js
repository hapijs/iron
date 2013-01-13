// Load modules

var Chai = require('chai');
var Hoek = require('hoek');
var Iron = process.env.TEST_COV ? require('../lib-cov') : require('../lib');


// Declare internals

var internals = {};


// Test shortcuts

var expect = Chai.expect;


describe('Iron', function () {

    var obj = {
        a: 1,
        b: 2,
        c: [3, 4, 5],
        d: {
            e: 'f'
        }
    };

    var password = 'some_not_random_password';

    it('turns object into a ticket than parses the ticket successfully', function (done) {

        Iron.seal(obj, password, Iron.defaults, function (err, sealed) {

            expect(err).to.not.exist;

            Iron.unseal(sealed, password, Iron.defaults, function (err, unsealed) {

                expect(err).to.not.exist;
                expect(unsealed).to.deep.equal(obj);
                done();
            });
        });
    });

    describe('#randomBits', function () {

        it('returns an error on invalid input', function (done) {

            Iron.randomBits(0, function (err, buffer) {

                expect(err).to.exist;
                expect(err.message).to.equal('Invalid random bits count');
                done();
            });
        });

        it('returns an error on invalid bits size', function (done) {

            Iron.randomBits(99999999999999999999, function (err, buffer) {

                expect(err).to.exist;
                expect(err.message).to.equal('Failed generating random bits: Argument #1 must be number > 0');
                done();
            });
        });
    });

    describe('#generateKey', function () {

        it('returns an error when password is missing', function (done) {

            Iron.generateKey(null, null, function (err) {

                expect(err).to.exist;
                expect(err.message).to.equal('Empty password');
                done();
            });
        });

        it('returns an error when options are missing', function (done) {

            Iron.generateKey('password', null, function (err) {

                expect(err).to.exist;
                expect(err.message).to.equal('Bad options');
                done();
            });
        });

        it('returns an error when an unknown algorithm is specified', function (done) {

            Iron.generateKey('password', { algorithm: 'unknown' }, function (err) {

                expect(err).to.exist;
                expect(err.message).to.equal('Unknown algorithm: unknown');
                done();
            });
        });

        it('returns an error when no salt or salt bits are provided', function (done) {

            var options = {
                algorithm: 'sha256',
                iterations: 2
            };

            Iron.generateKey('password', options, function (err) {

                expect(err).to.exist;
                expect(err.message).to.equal('Missing salt or saltBits options');
                done();
            });
        });

        it('returns an error when invalid salt bits are provided', function (done) {

            var options = {
                saltBits: 99999999999999999999,
                algorithm: 'sha256',
                iterations: 2
            };

            Iron.generateKey('password', options, function (err) {

                expect(err).to.exist;
                expect(err.message).to.equal('Failed generating random bits: Argument #1 must be number > 0');
                done();
            });
        });

        it('returns an error when randomBits fails', function (done) {

            var orig = Iron.randomBits;
            Iron.randomBits = function (bits, callback) {

                return callback(new Error('fake'));
            };

            var options = Hoek.clone(Iron.defaults.encryptionKey);
            options.salt = 'abcdefg';
            Iron.generateKey('password', options, function (err, result) {

                Iron.randomBits = orig;
                expect(err).to.exist;
                expect(err.message).to.equal('fake');
                done();
            });
        });
    });

    describe('#encrypt', function () {

        it('returns an error when password is missing', function (done) {

            Iron.encrypt(null, null, 'data', function (err, encrypted, key) {

                expect(err).to.exist;
                expect(err.message).to.equal('Empty password');
                done();
            });
        });
    });

    describe('#decrypt', function () {

        it('returns an error when password is missing', function (done) {

            Iron.decrypt(null, null, 'data', function (err, encrypted, key) {

                expect(err).to.exist;
                expect(err.message).to.equal('Empty password');
                done();
            });
        });
    });

    describe('#hmacWithPassword ', function () {

        it('returns an error when password is missing', function (done) {

            Iron.hmacWithPassword(null, null, 'data', function (err, result) {

                expect(err).to.exist;
                expect(err.message).to.equal('Empty password');
                done();
            });
        });
    });

    describe('#seal', function () {

        it('returns an error when password is missing', function (done) {

            Iron.seal('data', null, {}, function (err, sealed) {

                expect(err).to.exist;
                expect(err.message).to.equal('Empty password');
                done();
            });
        });

        it('returns an error when integrityKey options are missing', function (done) {

            var options = {
                encryptionKey: {
                    saltBits: 256,
                    algorithm: 'aes-256-cbc',
                    iterations: 1
                },
                integrityKey: {}
            };

            Iron.seal('data', 'password', options, function (err, sealed) {

                expect(err).to.exist;
                expect(err.message).to.equal('Unknown algorithm: undefined');
                done();
            });
        });
    });

    describe('#unseal', function () {

        it('unseals a ticket', function (done) {

            var ticket = '40ca744d63713c0e4a09cc16621083ecededf1e2103db52201f2712b8c579eeb:AcFbQ6iQEVW-Chn1w3v9-x5An__p4W5FsfqGPQyQZso:3d8b146df53292f10b311a1ed24b4a03279986fa886d3dc065faa0e93151f6fd:mEkHrrYuNk7MzUP19neFIQ:nQ_A39ciP2TTazIgcDGuPHeyVjcyBmtV1gGxkhSpnFL5KBCnK0WfOrEzbrZeM05S';
            Iron.unseal(ticket, password, Iron.defaults, function (err, unsealed) {

                expect(err).to.not.exist;
                expect(unsealed).to.deep.equal(obj);
                done();
            });
        });

        it('returns an error when number of sealed components is wrong', function (done) {

            var ticket = 'x:40ca744d63713c0e4a09cc16621083ecededf1e2103db52201f2712b8c579eeb:AcFbQ6iQEVW-Chn1w3v9-x5An__p4W5FsfqGPQyQZso:3d8b146df53292f10b311a1ed24b4a03279986fa886d3dc065faa0e93151f6fd:mEkHrrYuNk7MzUP19neFIQ:nQ_A39ciP2TTazIgcDGuPHeyVjcyBmtV1gGxkhSpnFL5KBCnK0WfOrEzbrZeM05S';
            Iron.unseal(ticket, password, Iron.defaults, function (err, unsealed) {

                expect(err).to.exist;
                expect(err.message).to.equal('Incorrect number of sealed components');
                done();
            });
        });

        it('returns an error when number of password is missing', function (done) {

            var ticket = '40ca744d63713c0e4a09cc16621083ecededf1e2103db52201f2712b8c579eeb:AcFbQ6iQEVW-Chn1w3v9-x5An__p4W5FsfqGPQyQZso:3d8b146df53292f10b311a1ed24b4a03279986fa886d3dc065faa0e93151f6fd:mEkHrrYuNk7MzUP19neFIQ:nQ_A39ciP2TTazIgcDGuPHeyVjcyBmtV1gGxkhSpnFL5KBCnK0WfOrEzbrZeM05S';
            Iron.unseal(ticket, null, Iron.defaults, function (err, unsealed) {

                expect(err).to.exist;
                expect(err.message).to.equal('Empty password');
                done();
            });
        });

        it('returns an error when integrity check fails', function (done) {

            var ticket = '40ca744d63713c0e4a09cc16621083ecededf1e2103db52201f2712b8c579eeb:XXAcFbQ6iQEVW-Chn1w3v9-x5An__p4W5FsfqGPQyQZso:3d8b146df53292f10b311a1ed24b4a03279986fa886d3dc065faa0e93151f6fd:mEkHrrYuNk7MzUP19neFIQ:nQ_A39ciP2TTazIgcDGuPHeyVjcyBmtV1gGxkhSpnFL5KBCnK0WfOrEzbrZeM05S';
            Iron.unseal(ticket, password, Iron.defaults, function (err, unsealed) {

                expect(err).to.exist;
                expect(err.message).to.equal('Bad hmac value');
                done();
            });
        });

        it('returns an error when decryption fails', function (done) {

            var macBaseString = '3d8b146df53292f10b311a1ed24b4a03279986fa886d3dc065faa0e93151f6fd:mEkHrrYuNk7MzUP19neFIQ:nQ_A39ciP2TTazIgcDGuPHeyVjcyBmtV1gGxkhSpnFL5KBCnK0WfOrEzbrZeM05S??';
            var options = Hoek.clone(Iron.defaults.integrityKey);
            options.salt = 'AcFbQ6iQEVW-Chn1w3v9-x5An__p4W5FsfqGPQyQZso';
            Iron.hmacWithPassword(password, options, macBaseString, function (err, mac) {

                var ticket = mac.salt + ':' + mac.digest + ':' + macBaseString;
                Iron.unseal(ticket, password, Iron.defaults, function (err, unsealed) {

                    expect(err).to.exist;
                    expect(err.message).to.equal('Invalid character');
                    done();
                });
            });
        });

        it('returns an error when decrypted object is invalid', function (done) {

            var badJson = '{asdasd';
            Iron.encrypt(password, Iron.defaults.encryptionKey, badJson, function (err, encrypted, key) {

                var encryptedB64 = Hoek.base64urlEncode(encrypted);
                var iv = Hoek.base64urlEncode(key.iv);
                var macBaseString = key.salt + ':' + iv + ':' + encryptedB64;
                Iron.hmacWithPassword(password, Iron.defaults.integrityKey, macBaseString, function (err, mac) {

                    var ticket = mac.salt + ':' + mac.digest + ':' + macBaseString;
                    Iron.unseal(ticket, password, Iron.defaults, function (err, unsealed) {

                        expect(err).to.exist;
                        expect(err.message).to.equal('Failed parsing sealed object JSON: Unexpected token a');
                        done();
                    });
                });
            });
        });
    });
});
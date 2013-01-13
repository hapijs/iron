// Load modules

var Chai = require('chai');
var Hoek = require('hoek');
var Iron = process.env.TEST_COV ? require('../lib-cov') : require('../lib');
var Cryptiles = require('cryptiles');


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

            var orig = Cryptiles.randomBits;
            Cryptiles.randomBits = function (bits) {

                return new Error('fake');
            };

            var options = Hoek.clone(Iron.defaults.encryptionKey);
            options.salt = 'abcdefg';
            Iron.generateKey('password', options, function (err, result) {

                Cryptiles.randomBits = orig;
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

            var ticket = '6b6102fe5d38adf169eb38545c5838043ce4789efa813c3a92dae3b314a4eff2:2vd2BkzOj3GE70MniYXtKVgEY-5PRvSfDAa5wL5pX-U:Fe26.1:5020531933fbd9f03c8862a8ddfa1a83865e5f3b3c2bfe3ba29e740eef24370a:Vvkp33V8DcEMpGBBOtY7qw:nzGw9V2gPgX5PbS_DRx6lHzDcXaMkdLE4op13uNsuU6aCXlmC2vr0fhY5LrjkioN';
            Iron.unseal(ticket, password, Iron.defaults, function (err, unsealed) {

                expect(err).to.not.exist;
                expect(unsealed).to.deep.equal(obj);
                done();
            });
        });

        it('returns an error when number of sealed components is wrong', function (done) {

            var ticket = 'x:6b6102fe5d38adf169eb38545c5838043ce4789efa813c3a92dae3b314a4eff2:2vd2BkzOj3GE70MniYXtKVgEY-5PRvSfDAa5wL5pX-U:Fe26.1:5020531933fbd9f03c8862a8ddfa1a83865e5f3b3c2bfe3ba29e740eef24370a:Vvkp33V8DcEMpGBBOtY7qw:nzGw9V2gPgX5PbS_DRx6lHzDcXaMkdLE4op13uNsuU6aCXlmC2vr0fhY5LrjkioN';
            Iron.unseal(ticket, password, Iron.defaults, function (err, unsealed) {

                expect(err).to.exist;
                expect(err.message).to.equal('Incorrect number of sealed components');
                done();
            });
        });

        it('returns an error when password is missing', function (done) {

            var ticket = '6b6102fe5d38adf169eb38545c5838043ce4789efa813c3a92dae3b314a4eff2:2vd2BkzOj3GE70MniYXtKVgEY-5PRvSfDAa5wL5pX-U:Fe26.1:5020531933fbd9f03c8862a8ddfa1a83865e5f3b3c2bfe3ba29e740eef24370a:Vvkp33V8DcEMpGBBOtY7qw:nzGw9V2gPgX5PbS_DRx6lHzDcXaMkdLE4op13uNsuU6aCXlmC2vr0fhY5LrjkioN';
            Iron.unseal(ticket, null, Iron.defaults, function (err, unsealed) {

                expect(err).to.exist;
                expect(err.message).to.equal('Empty password');
                done();
            });
        });

        it('returns an error when mac prefix is wrong', function (done) {

            var ticket = '6b6102fe5d38adf169eb38545c5838043ce4789efa813c3a92dae3b314a4eff2:2vd2BkzOj3GE70MniYXtKVgEY-5PRvSfDAa5wL5pX-U:Fe26.2:5020531933fbd9f03c8862a8ddfa1a83865e5f3b3c2bfe3ba29e740eef24370a:Vvkp33V8DcEMpGBBOtY7qw:nzGw9V2gPgX5PbS_DRx6lHzDcXaMkdLE4op13uNsuU6aCXlmC2vr0fhY5LrjkioN';
            Iron.unseal(ticket, password, Iron.defaults, function (err, unsealed) {

                expect(err).to.exist;
                expect(err.message).to.equal('Wrong mac prefix');
                done();
            });
        });

        it('returns an error when integrity check fails', function (done) {

            var ticket = 'X6b6102fe5d38adf169eb38545c5838043ce4789efa813c3a92dae3b314a4eff2:2vd2BkzOj3GE70MniYXtKVgEY-5PRvSfDAa5wL5pX-U:Fe26.1:5020531933fbd9f03c8862a8ddfa1a83865e5f3b3c2bfe3ba29e740eef24370a:Vvkp33V8DcEMpGBBOtY7qw:nzGw9V2gPgX5PbS_DRx6lHzDcXaMkdLE4op13uNsuU6aCXlmC2vr0fhY5LrjkioN';
            Iron.unseal(ticket, password, Iron.defaults, function (err, unsealed) {

                expect(err).to.exist;
                expect(err.message).to.equal('Bad hmac value');
                done();
            });
        });

        it('returns an error when decryption fails', function (done) {

            var macBaseString = 'Fe26.1:5020531933fbd9f03c8862a8ddfa1a83865e5f3b3c2bfe3ba29e740eef24370a:Vvkp33V8DcEMpGBBOtY7qw:nzGw9V2gPgX5PbS_DRx6lHzDcXaMkdLE4op13uNsuU6aCXlmC2vr0fhY5LrjkioN??';
            var options = Hoek.clone(Iron.defaults.integrityKey);
            options.salt = '2vd2BkzOj3GE70MniYXtKVgEY-5PRvSfDAa5wL5pX-U';
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
                var macBaseString = Iron.macPrefix + ':' + key.salt + ':' + iv + ':' + encryptedB64;
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
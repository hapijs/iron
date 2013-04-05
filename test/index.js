// Load modules

var Crypto = require('crypto');
var Lab = require('lab');
var Hoek = require('hoek');
var Iron = require('../lib');
var Cryptiles = require('cryptiles');


// Declare internals

var internals = {};


// Test shortcuts

var expect = Lab.expect;
var before = Lab.before;
var after = Lab.after;
var describe = Lab.experiment;
var it = Lab.test;


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

            Iron.unseal(sealed, { 'default': password }, Iron.defaults, function (err, unsealed) {

                expect(err).to.not.exist;
                expect(unsealed).to.deep.equal(obj);
                done();
            });
        });
    });

    it('turns object into a ticket than parses the ticket successfully (password buffer)', function (done) {

        var key = Cryptiles.randomBits(256);
        Iron.seal(obj, key, Iron.defaults, function (err, sealed) {

            expect(err).to.not.exist;

            Iron.unseal(sealed, { 'default': key }, Iron.defaults, function (err, unsealed) {

                expect(err).to.not.exist;
                expect(unsealed).to.deep.equal(obj);
                done();
            });
        });
    });

    it('fails to turns object into a ticket (password buffer too short)', function (done) {

        var key = Cryptiles.randomBits(128);
        Iron.seal(obj, key, Iron.defaults, function (err, sealed) {

            expect(err).to.exist;
            expect(err.message).to.equal('Key buffer (password) too small');
            done();
        });
    });

    it('turns object into a ticket than parses the ticket successfully (password object)', function (done) {

        Iron.seal(obj, { id: '1', secret: password }, Iron.defaults, function (err, sealed) {

            expect(err).to.not.exist;

            Iron.unseal(sealed, { '1': password }, Iron.defaults, function (err, unsealed) {

                expect(err).to.not.exist;
                expect(unsealed).to.deep.equal(obj);
                done();
            });
        });
    });

    it('fails to parse a sealed object when password not found', function (done) {

        Iron.seal(obj, { id: '1', secret: password }, Iron.defaults, function (err, sealed) {

            expect(err).to.not.exist;

            Iron.unseal(sealed, { '2': password }, Iron.defaults, function (err, unsealed) {

                expect(err).to.exist;
                expect(err.message).to.equal('Cannot find password: 1');
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

        it('returns an error when Cryptiles.randomBits fails', function (done) {

            var options = Hoek.clone(Iron.defaults.encryption);
            options.salt = 'abcdefg';
            options.algorithm = 'x';
            Iron.algorithms['x'] = { keyBits: 256, ivBits: -1 };

            Iron.generateKey('password', options, function (err, result) {

                expect(err).to.exist;
                expect(err.message).to.equal('Invalid random bits count');
                done();
            });
        });

        it('returns an error when Crypto.pbkdf2 fails', function (done) {

            var orig = Crypto.pbkdf2;
            Crypto.pbkdf2 = function (v1, v2, v3, v4, callback) {

                return callback(new Error('fake'));
            };

            Iron.generateKey('password', Iron.defaults.encryption, function (err, result) {

                Crypto.pbkdf2 = orig;
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

        it('produces the same mac when used with buffer password', function (done) {

            var data = 'Not so random';
            var key = Cryptiles.randomBits(256);
            var hmac = Crypto.createHmac(Iron.defaults.integrity.algorithm, key).update(data);
            var digest = hmac.digest('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/\=/g, '');

            Iron.hmacWithPassword(key, Iron.defaults.integrity, data, function (err, result) {

                expect(err).to.not.exist;
                expect(result.digest).to.equal(digest);
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

        it('returns an error when integrity options are missing', function (done) {

            var options = {
                encryption: {
                    saltBits: 256,
                    algorithm: 'aes-256-cbc',
                    iterations: 1
                },
                integrity: {}
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

            var ticket = 'Fe26.1**f9eebba02da4315acd770116b07a32aa4e7a7fe5fa89e0b89d2157c5d05891ef*_vDwAc4vMs448xng9Xgc2g*lc48O_ArSZlw3cGHkYKEH0XWHimPPQV9V52vPEimWgs2FHxyoAS5gk1W20-QHrIA*4a4818478f2d3b12536d4f0844ecc8c37d10e99b2f96bd63ab212bb1dc98aa3e*S-LG1fLECD_I2Pw2TsIXosc8fhKEsjil54ifAfEv5Xw';
            Iron.unseal(ticket, password, Iron.defaults, function (err, unsealed) {

                expect(err).to.not.exist;
                expect(unsealed).to.deep.equal(obj);
                done();
            });
        });

        it('returns an error when number of sealed components is wrong', function (done) {

            var ticket = 'x*Fe26.1**f9eebba02da4315acd770116b07a32aa4e7a7fe5fa89e0b89d2157c5d05891ef*_vDwAc4vMs448xng9Xgc2g*lc48O_ArSZlw3cGHkYKEH0XWHimPPQV9V52vPEimWgs2FHxyoAS5gk1W20-QHrIA*4a4818478f2d3b12536d4f0844ecc8c37d10e99b2f96bd63ab212bb1dc98aa3e*S-LG1fLECD_I2Pw2TsIXosc8fhKEsjil54ifAfEv5Xw';
            Iron.unseal(ticket, password, Iron.defaults, function (err, unsealed) {

                expect(err).to.exist;
                expect(err.message).to.equal('Incorrect number of sealed components');
                done();
            });
        });

        it('returns an error when password is missing', function (done) {

            var ticket = 'Fe26.1**f9eebba02da4315acd770116b07a32aa4e7a7fe5fa89e0b89d2157c5d05891ef*_vDwAc4vMs448xng9Xgc2g*lc48O_ArSZlw3cGHkYKEH0XWHimPPQV9V52vPEimWgs2FHxyoAS5gk1W20-QHrIA*4a4818478f2d3b12536d4f0844ecc8c37d10e99b2f96bd63ab212bb1dc98aa3e*S-LG1fLECD_I2Pw2TsIXosc8fhKEsjil54ifAfEv5Xw';
            Iron.unseal(ticket, null, Iron.defaults, function (err, unsealed) {

                expect(err).to.exist;
                expect(err.message).to.equal('Empty password');
                done();
            });
        });

        it('returns an error when mac prefix is wrong', function (done) {

            var ticket = 'Fe27.1**f9eebba02da4315acd770116b07a32aa4e7a7fe5fa89e0b89d2157c5d05891ef*_vDwAc4vMs448xng9Xgc2g*lc48O_ArSZlw3cGHkYKEH0XWHimPPQV9V52vPEimWgs2FHxyoAS5gk1W20-QHrIA*4a4818478f2d3b12536d4f0844ecc8c37d10e99b2f96bd63ab212bb1dc98aa3e*S-LG1fLECD_I2Pw2TsIXosc8fhKEsjil54ifAfEv5Xw';
            Iron.unseal(ticket, password, Iron.defaults, function (err, unsealed) {

                expect(err).to.exist;
                expect(err.message).to.equal('Wrong mac prefix');
                done();
            });
        });

        it('returns an error when integrity check fails', function (done) {

            var ticket = 'Fe26.1**f9eebba02da4315acd770116b07a32aa4e7a7fe5fa89e0b89d2157c5d05891ef*_vDwAc4vMs448xng9Xgc2g*lc48O_ArSZlw3cGHkYKEH0XWHimPPQV9V52vPEimWgs2FHxyoAS5gk1W20-QHrIA*4a4818478f2d3b12536d4f0844ecc8c37d10e99b2f96bd63ab212bb1dc98aa3e*S-LG1fLECD_I2Pw2TsIXosc8fhKEsjil54ifAfEv5XwX';
            Iron.unseal(ticket, password, Iron.defaults, function (err, unsealed) {

                expect(err).to.exist;
                expect(err.message).to.equal('Bad hmac value');
                done();
            });
        });

        it('returns an error when decryption fails', function (done) {

            var macBaseString = 'Fe26.1**f9eebba02da4315acd770116b07a32aa4e7a7fe5fa89e0b89d2157c5d05891ef*_vDwAc4vMs448xng9Xgc2g*lc48O_ArSZlw3cGHkYKEH0XWHimPPQV9V52vPEimWgs2FHxyoAS5gk1W20-QHrIA??';
            var options = Hoek.clone(Iron.defaults.integrity);
            options.salt = '4a4818478f2d3b12536d4f0844ecc8c37d10e99b2f96bd63ab212bb1dc98aa3e';
            Iron.hmacWithPassword(password, options, macBaseString, function (err, mac) {

                var ticket = macBaseString + '*' + mac.salt + '*' + mac.digest;
                Iron.unseal(ticket, password, Iron.defaults, function (err, unsealed) {

                    expect(err).to.exist;
                    expect(err.message).to.equal('Invalid character');
                    done();
                });
            });
        });

        it('returns an error when decrypted object is invalid', function (done) {

            var badJson = '{asdasd';
            Iron.encrypt(password, Iron.defaults.encryption, badJson, function (err, encrypted, key) {

                var encryptedB64 = Hoek.base64urlEncode(encrypted);
                var iv = Hoek.base64urlEncode(key.iv);
                var macBaseString = Iron.macPrefix + '**' + key.salt + '*' + iv + '*' + encryptedB64;
                Iron.hmacWithPassword(password, Iron.defaults.integrity, macBaseString, function (err, mac) {

                    var ticket = macBaseString + '*' + mac.salt + '*' + mac.digest;
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
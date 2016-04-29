'use strict';

// Load modules

const Crypto = require('crypto');
const Code = require('code');
const Cryptiles = require('cryptiles');
const Hoek = require('hoek');
const Iron = require('../lib');
const Lab = require('lab');


// Declare internals

const internals = {};


// Test shortcuts

const lab = exports.lab = Lab.script();
const describe = lab.describe;
const it = lab.it;
const expect = Code.expect;


describe('Iron', () => {

    const obj = {
        a: 1,
        b: 2,
        c: [3, 4, 5],
        d: {
            e: 'f'
        }
    };

    const password = 'some_not_random_password_that_is_also_long_enough';

    it('turns object into a ticket than parses the ticket successfully', (done) => {

        Iron.seal(obj, password, Iron.defaults, (err, sealed) => {

            expect(err).to.not.exist();

            Iron.unseal(sealed, { 'default': password }, Iron.defaults, (err, unsealed) => {

                expect(err).to.not.exist();
                expect(unsealed).to.deep.equal(obj);
                done();
            });
        });
    });

    it('unseal and sealed object with expiration', (done) => {

        const options = Hoek.clone(Iron.defaults);
        options.ttl = 200;
        Iron.seal(obj, password, options, (err, sealed) => {

            expect(err).to.not.exist();

            Iron.unseal(sealed, { 'default': password }, Iron.defaults, (err, unsealed) => {

                expect(err).to.not.exist();
                expect(unsealed).to.deep.equal(obj);
                done();
            });
        });
    });

    it('unseal and sealed object with expiration and time offset', (done) => {

        const options = Hoek.clone(Iron.defaults);
        options.ttl = 200;
        options.localtimeOffsetMsec = -100000;
        Iron.seal(obj, password, options, (err, sealed) => {

            expect(err).to.not.exist();

            const options2 = Hoek.clone(Iron.defaults);
            options2.localtimeOffsetMsec = -100000;
            Iron.unseal(sealed, { 'default': password }, options2, (err, unsealed) => {

                expect(err).to.not.exist();
                expect(unsealed).to.deep.equal(obj);
                done();
            });
        });
    });

    it('turns object into a ticket than parses the ticket successfully (password buffer)', (done) => {

        const key = Cryptiles.randomBits(256);
        Iron.seal(obj, key, Iron.defaults, (err, sealed) => {

            expect(err).to.not.exist();

            Iron.unseal(sealed, { 'default': key }, Iron.defaults, (err, unsealed) => {

                expect(err).to.not.exist();
                expect(unsealed).to.deep.equal(obj);
                done();
            });
        });
    });

    it('fails to turns object into a ticket (password buffer too short)', (done) => {

        const key = Cryptiles.randomBits(128);
        Iron.seal(obj, key, Iron.defaults, (err, sealed) => {

            expect(err).to.exist();
            expect(err.message).to.equal('Key buffer (password) too small');
            done();
        });
    });

    it('turns object into a ticket than parses the ticket successfully (password object)', (done) => {

        Iron.seal(obj, { id: '1', secret: password }, Iron.defaults, (err, sealed) => {

            expect(err).to.not.exist();

            Iron.unseal(sealed, { '1': password }, Iron.defaults, (err, unsealed) => {

                expect(err).to.not.exist();
                expect(unsealed).to.deep.equal(obj);
                done();
            });
        });
    });

    it('handles separate password buffers (password object)', (done) => {

        const key = {
            id: '1',
            encryption: Cryptiles.randomBits(256),
            integrity: Cryptiles.randomBits(256)
        };

        Iron.seal(obj, key, Iron.defaults, (err, sealed) => {

            expect(err).to.not.exist();

            Iron.unseal(sealed, { '1': key }, Iron.defaults, (err, unsealed) => {

                expect(err).to.not.exist();
                done();
            });
        });
    });

    it('handles a common password buffer (password object)', (done) => {

        const key = {
            id: '1',
            secret: Cryptiles.randomBits(256)
        };

        Iron.seal(obj, key, Iron.defaults, (err, sealed) => {

            expect(err).to.not.exist();

            Iron.unseal(sealed, { '1': key }, Iron.defaults, (err, unsealed) => {

                expect(err).to.not.exist();
                done();
            });
        });
    });

    it('fails to parse a sealed object when password not found', (done) => {

        Iron.seal(obj, { id: '1', secret: password }, Iron.defaults, (err, sealed) => {

            expect(err).to.not.exist();

            Iron.unseal(sealed, { '2': password }, Iron.defaults, (err, unsealed) => {

                expect(err).to.exist();
                expect(err.message).to.equal('Cannot find password: 1');
                done();
            });
        });
    });

    describe('#generateKey', () => {

        it('returns an error when password is missing', (done) => {

            Iron.generateKey(null, null, (err) => {

                expect(err).to.exist();
                expect(err.message).to.equal('Empty password');
                done();
            });
        });

        it('returns an error when password is too short', (done) => {

            Iron.generateKey('password', Iron.defaults.encryption, (err) => {

                expect(err).to.exist();
                expect(err.message).to.equal('Password string too short (min 32 characters required)');
                done();
            });
        });

        it('returns an error when options are missing', (done) => {

            Iron.generateKey(password, null, (err) => {

                expect(err).to.exist();
                expect(err.message).to.equal('Bad options');
                done();
            });
        });

        it('returns an error when an unknown algorithm is specified', (done) => {

            Iron.generateKey(password, { algorithm: 'unknown' }, (err) => {

                expect(err).to.exist();
                expect(err.message).to.equal('Unknown algorithm: unknown');
                done();
            });
        });

        it('returns an error when no salt or salt bits are provided', (done) => {

            const options = {
                algorithm: 'sha256',
                iterations: 2
            };

            Iron.generateKey(password, options, (err) => {

                expect(err).to.exist();
                expect(err.message).to.equal('Missing salt or saltBits options');
                done();
            });
        });

        it('returns an error when invalid salt bits are provided', (done) => {

            const options = {
                saltBits: 99999999999999999999,
                algorithm: 'sha256',
                iterations: 2
            };

            Iron.generateKey(password, options, (err) => {

                expect(err).to.exist();
                expect(err.message).to.match(/Failed generating random bits/);
                done();
            });
        });

        it('returns an error when Cryptiles.randomBits fails', (done) => {

            const options = Hoek.clone(Iron.defaults.encryption);
            options.salt = 'abcdefg';
            options.algorithm = 'x';
            Iron.algorithms.x = { keyBits: 256, ivBits: -1 };

            Iron.generateKey(password, options, (err, result) => {

                expect(err).to.exist();
                expect(err.message).to.equal('Invalid random bits count');
                done();
            });
        });

        it('returns an error when Crypto.pbkdf2 fails', (done) => {

            const orig = Crypto.pbkdf2;
            Crypto.pbkdf2 = function (v1, v2, v3, v4, v5, callback) {

                return callback(new Error('fake'));
            };

            Iron.generateKey(password, Iron.defaults.encryption, (err, result) => {

                Crypto.pbkdf2 = orig;
                expect(err).to.exist();
                expect(err.message).to.equal('fake');
                done();
            });
        });
    });

    describe('#encrypt', () => {

        it('returns an error when password is missing', (done) => {

            Iron.encrypt(null, null, 'data', (err, encrypted, key) => {

                expect(err).to.exist();
                expect(err.message).to.equal('Empty password');
                done();
            });
        });
    });

    describe('#decrypt', () => {

        it('returns an error when password is missing', (done) => {

            Iron.decrypt(null, null, 'data', (err, encrypted, key) => {

                expect(err).to.exist();
                expect(err.message).to.equal('Empty password');
                done();
            });
        });
    });

    describe('#hmacWithPassword ', () => {

        it('returns an error when password is missing', (done) => {

            Iron.hmacWithPassword(null, null, 'data', (err, result) => {

                expect(err).to.exist();
                expect(err.message).to.equal('Empty password');
                done();
            });
        });

        it('produces the same mac when used with buffer password', (done) => {

            const data = 'Not so random';
            const key = Cryptiles.randomBits(256);
            const hmac = Crypto.createHmac(Iron.defaults.integrity.algorithm, key).update(data);
            const digest = hmac.digest('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/\=/g, '');

            Iron.hmacWithPassword(key, Iron.defaults.integrity, data, (err, result) => {

                expect(err).to.not.exist();
                expect(result.digest).to.equal(digest);
                done();
            });
        });
    });

    describe('#seal', () => {

        it('returns an error when password is missing', (done) => {

            Iron.seal('data', null, {}, (err, sealed) => {

                expect(err).to.exist();
                expect(err.message).to.equal('Empty password');
                done();
            });
        });

        it('returns an error when integrity options are missing', (done) => {

            const options = {
                encryption: {
                    saltBits: 256,
                    algorithm: 'aes-256-cbc',
                    iterations: 1
                },
                integrity: {}
            };

            Iron.seal('data', password, options, (err, sealed) => {

                expect(err).to.exist();
                expect(err.message).to.equal('Unknown algorithm: undefined');
                done();
            });
        });

        it('returns an error when password.id is invalid', (done) => {

            Iron.seal('data', { id: 'asd$', secret: 'asd' }, {}, (err, sealed) => {

                expect(err).to.exist();
                expect(err.message).to.equal('Invalid password id');
                done();
            });
        });
    });

    describe('#unseal', () => {

        it('unseals a ticket', (done) => {

            const ticket = 'Fe26.2**0cdd607945dd1dffb7da0b0bf5f1a7daa6218cbae14cac51dcbd91fb077aeb5b*aOZLCKLhCt0D5IU1qLTtYw*g0ilNDlQ3TsdFUqJCqAm9iL7Wa60H7eYcHL_5oP136TOJREkS3BzheDC1dlxz5oJ**05b8943049af490e913bbc3a2485bee2aaf7b823f4c41d0ff0b7c168371a3772*R8yscVdTBRMdsoVbdDiFmUL8zb-c3PQLGJn4Y8C-AqI';
            Iron.unseal(ticket, password, Iron.defaults, (err, unsealed) => {

                expect(err).to.not.exist();
                expect(unsealed).to.deep.equal(obj);
                done();
            });
        });

        it('returns an error when number of sealed components is wrong', (done) => {

            const ticket = 'x*Fe26.2**a6dc6339e5ea5dfe7a135631cf3b7dcf47ea38246369d45767c928ea81781694*D3DLEoi-Hn3c972TPpZXqw*mCBhmhHhRKk9KtBjwu3h-1lx1MHKkgloQPKRkQZxpnDwYnFkb3RqdVTQRcuhGf4M**ff2bf988aa0edf2b34c02d220a45c4a3c572dac6b995771ed20de58da919bfa5*HfWzyJlz_UP9odmXvUaVK1TtdDuOCaezr-TAg2GjBCU';
            Iron.unseal(ticket, password, Iron.defaults, (err, unsealed) => {

                expect(err).to.exist();
                expect(err.message).to.equal('Incorrect number of sealed components');
                done();
            });
        });

        it('returns an error when password is missing', (done) => {

            const ticket = 'Fe26.2**a6dc6339e5ea5dfe7a135631cf3b7dcf47ea38246369d45767c928ea81781694*D3DLEoi-Hn3c972TPpZXqw*mCBhmhHhRKk9KtBjwu3h-1lx1MHKkgloQPKRkQZxpnDwYnFkb3RqdVTQRcuhGf4M**ff2bf988aa0edf2b34c02d220a45c4a3c572dac6b995771ed20de58da919bfa5*HfWzyJlz_UP9odmXvUaVK1TtdDuOCaezr-TAg2GjBCU';
            Iron.unseal(ticket, null, Iron.defaults, (err, unsealed) => {

                expect(err).to.exist();
                expect(err.message).to.equal('Empty password');
                done();
            });
        });

        it('returns an error when mac prefix is wrong', (done) => {

            const ticket = 'Fe27.2**a6dc6339e5ea5dfe7a135631cf3b7dcf47ea38246369d45767c928ea81781694*D3DLEoi-Hn3c972TPpZXqw*mCBhmhHhRKk9KtBjwu3h-1lx1MHKkgloQPKRkQZxpnDwYnFkb3RqdVTQRcuhGf4M**ff2bf988aa0edf2b34c02d220a45c4a3c572dac6b995771ed20de58da919bfa5*HfWzyJlz_UP9odmXvUaVK1TtdDuOCaezr-TAg2GjBCU';
            Iron.unseal(ticket, password, Iron.defaults, (err, unsealed) => {

                expect(err).to.exist();
                expect(err.message).to.equal('Wrong mac prefix');
                done();
            });
        });

        it('returns an error when integrity check fails', (done) => {

            const ticket = 'Fe26.2**b3ad22402ccc60fa4d527f7d1c9ff2e37e9b2e5723e9e2ffba39a489e9849609*QKCeXLs6Rp7f4LL56V7hBg*OvZEoAq_nGOpA1zae-fAtl7VNCNdhZhCqo-hWFCBeWuTTpSupJ7LxQqzSQBRAcgw**72018a21d3fac5c1608a0f9e461de0fcf17b2befe97855978c17a793faa01db1*Qj53DFE3GZd5yigt-mVl9lnp0VUoSjh5a5jgDmod1EZ';
            Iron.unseal(ticket, password, Iron.defaults, (err, unsealed) => {

                expect(err).to.exist();
                expect(err.message).to.equal('Bad hmac value');
                done();
            });
        });

        it('returns an error when decryption fails', (done) => {

            const macBaseString = 'Fe26.2**a6dc6339e5ea5dfe7a135631cf3b7dcf47ea38246369d45767c928ea81781694*D3DLEoi-Hn3c972TPpZXqw*mCBhmhHhRKk9KtBjwu3h-1lx1MHKkgloQPKRkQZxpnDwYnFkb3RqdVTQRcuhGf4M??*';
            const options = Hoek.clone(Iron.defaults.integrity);
            options.salt = 'ff2bf988aa0edf2b34c02d220a45c4a3c572dac6b995771ed20de58da919bfa5';
            Iron.hmacWithPassword(password, options, macBaseString, (err, mac) => {

                expect(err).to.not.exist();

                const ticket = macBaseString + '*' + mac.salt + '*' + mac.digest;
                Iron.unseal(ticket, password, Iron.defaults, (err, unsealed) => {

                    expect(err).to.exist();
                    expect(err.message).to.equal('Invalid character');
                    done();
                });
            });
        });

        it('returns an error when iv base64 decoding fails', (done) => {

            const macBaseString = 'Fe26.2**a6dc6339e5ea5dfe7a135631cf3b7dcf47ea38246369d45767c928ea81781694*D3DLEoi-Hn3c972TPpZXqw??*mCBhmhHhRKk9KtBjwu3h-1lx1MHKkgloQPKRkQZxpnDwYnFkb3RqdVTQRcuhGf4M*';
            const options = Hoek.clone(Iron.defaults.integrity);
            options.salt = 'ff2bf988aa0edf2b34c02d220a45c4a3c572dac6b995771ed20de58da919bfa5';
            Iron.hmacWithPassword(password, options, macBaseString, (err, mac) => {

                expect(err).to.not.exist();

                const ticket = macBaseString + '*' + mac.salt + '*' + mac.digest;
                Iron.unseal(ticket, password, Iron.defaults, (err, unsealed) => {

                    expect(err).to.exist();
                    expect(err.message).to.equal('Invalid character');
                    done();
                });
            });
        });

        it('returns an error when decrypted object is invalid', (done) => {

            const badJson = '{asdasd';
            Iron.encrypt(password, Iron.defaults.encryption, badJson, (err, encrypted, key) => {

                expect(err).to.not.exist();

                const encryptedB64 = Hoek.base64urlEncode(encrypted);
                const iv = Hoek.base64urlEncode(key.iv);
                const macBaseString = Iron.macPrefix + '**' + key.salt + '*' + iv + '*' + encryptedB64 + '*';
                Iron.hmacWithPassword(password, Iron.defaults.integrity, macBaseString, (err, mac) => {

                    expect(err).to.not.exist();

                    const ticket = macBaseString + '*' + mac.salt + '*' + mac.digest;
                    Iron.unseal(ticket, password, Iron.defaults, (err, unsealed) => {

                        expect(err).to.exist();
                        expect(err.message).to.match(/Failed parsing sealed object JSON: Unexpected token a/);
                        done();
                    });
                });
            });
        });

        it('returns an error when expired', (done) => {

            const macBaseString = 'Fe26.2**a38dc7a7bf2f8ff650b103d8c669d76ad219527fbfff3d98e3b30bbecbe9bd3b*nTsatb7AQE1t0uMXDx-2aw*uIO5bRFTwEBlPC1Nd_hfSkZfqxkxuY1EO2Be_jJPNQCqFNumRBjQAl8WIKBW1beF*1380495854060';
            const options = Hoek.clone(Iron.defaults.integrity);
            options.salt = 'e4fe33b6dc4c7ef5ad7907f015deb7b03723b03a54764aceeb2ab1235cc8dce3';
            Iron.hmacWithPassword(password, options, macBaseString, (err, mac) => {

                expect(err).to.not.exist();

                const ticket = macBaseString + '*' + mac.salt + '*' + mac.digest;
                Iron.unseal(ticket, password, Iron.defaults, (err, unsealed) => {

                    expect(err).to.exist();
                    expect(err.message).to.equal('Expired seal');
                    done();
                });
            });
        });

        it('returns an error when expiration NaN', (done) => {

            const macBaseString = 'Fe26.2**a38dc7a7bf2f8ff650b103d8c669d76ad219527fbfff3d98e3b30bbecbe9bd3b*nTsatb7AQE1t0uMXDx-2aw*uIO5bRFTwEBlPC1Nd_hfSkZfqxkxuY1EO2Be_jJPNQCqFNumRBjQAl8WIKBW1beF*a';
            const options = Hoek.clone(Iron.defaults.integrity);
            options.salt = 'e4fe33b6dc4c7ef5ad7907f015deb7b03723b03a54764aceeb2ab1235cc8dce3';
            Iron.hmacWithPassword(password, options, macBaseString, (err, mac) => {

                expect(err).to.not.exist();

                const ticket = macBaseString + '*' + mac.salt + '*' + mac.digest;
                Iron.unseal(ticket, password, Iron.defaults, (err, unsealed) => {

                    expect(err).to.exist();
                    expect(err.message).to.equal('Invalid expiration');
                    done();
                });
            });
        });
    });
});

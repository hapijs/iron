// Load modules

var Chai = require('chai');
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

    it('unseals a ticket', function (done) {

        var ticket = '40ca744d63713c0e4a09cc16621083ecededf1e2103db52201f2712b8c579eeb:AcFbQ6iQEVW-Chn1w3v9-x5An__p4W5FsfqGPQyQZso:3d8b146df53292f10b311a1ed24b4a03279986fa886d3dc065faa0e93151f6fd:mEkHrrYuNk7MzUP19neFIQ:nQ_A39ciP2TTazIgcDGuPHeyVjcyBmtV1gGxkhSpnFL5KBCnK0WfOrEzbrZeM05S';
        Iron.unseal(ticket, password, Iron.defaults, function (err, unsealed) {

            expect(err).to.not.exist;
            expect(unsealed).to.deep.equal(obj);
            done();
        });
    });

    describe('#generateKey', function () {

        it('returns an error when password is missing', function (done) {

            Iron.generateKey(null, null, function (err) {

                expect(err).to.be.instanceOf(Error);
                done();
            });
        });

        it('returns an error when options are missing', function (done) {

            Iron.generateKey('password', null, function (err) {

                expect(err).to.be.instanceOf(Error);
                done();
            });
        });

        it('returns an error when an unknown algorithm is specified', function (done) {

            Iron.generateKey('password', { algorithm: 'unknown' }, function (err) {

                expect(err).to.be.instanceOf(Error);
                done();
            });
        });

        it('returns an error when no salt or salt bits are provided', function (done) {

            var options = {
                algorithm: 'sha256',
                iterations: 2
            };

            Iron.generateKey('password', options, function (err) {

                expect(err).to.be.instanceOf(Error);
                done();
            });
        });

        it('returns the key when valid algorithm and salt provided', function (done) {

            var options = {
                algorithm: 'sha256',
                salt: 'test',
                iterations: 2
            };

            Iron.generateKey('password', options, function (err, result) {

                expect(err).to.not.exist;
                expect(result).to.exist;
                done();
            });
        });
    });
});
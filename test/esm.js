'use strict';

const Code = require('@hapi/code');
const Lab = require('@hapi/lab');


const { before, describe, it } = exports.lab = Lab.script();
const expect = Code.expect;


describe('import()', () => {

    let Ion;

    before(async () => {

        Ion = await import('../lib/index.js');
    });

    it('exposes all methods and classes as named imports', () => {

        expect(Object.keys(Ion)).to.equal([
            'algorithms',
            'decrypt',
            'default',
            'defaults',
            'encrypt',
            'generateKey',
            'hmacWithPassword',
            'macFormatVersion',
            'macPrefix',
            'seal',
            'unseal'
        ]);
    });
});

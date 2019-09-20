import * as Iron from '..';
import * as Lab from '@hapi/lab';

const Cryptiles = require('@hapi/cryptiles');


const { expect } = Lab.types;


const password = 'some_not_random_password_that_is_also_long_enough';

const buffer = Cryptiles.randomBits(256);

const defaults = {
    encryption: {
        saltBits: 256,
        algorithm: 'aes-256-cbc',
        iterations: 1,
        minPasswordlength: 32
    },

    integrity: {
        saltBits: 256,
        algorithm: 'sha256',
        iterations: 1,
        minPasswordlength: 32
    },

    ttl: 0,
    timestampSkewSec: 60,
    localtimeOffsetMsec: 0
} as Iron.SealOptions;

const options = {
    saltBits: 256,
    salt: '4d8nr9q384nr9q384nr93q8nruq9348run',
    algorithm: 'aes-128-ctr',
    iterations: 10000,
    iv: 'sdfsdfsdfsdfscdrgercgesrcgsercg',
    minPasswordlength: 32
} as Iron.GenerateKeyOptions;


// generateKey()

Iron.generateKey(password, options)
Iron.generateKey(password, defaults.encryption)

expect.type<Iron.Key>(await Iron.generateKey(password, options))

expect.error(Iron.generateKey(256, options))
expect.error(Iron.generateKey({ foo: "bar" }, options))
expect.error(Iron.generateKey('password', 'password'))
expect.error(Iron.generateKey('password'))


// encrypt()

Iron.encrypt(password, options, "hello")
Iron.encrypt(buffer, options, "hello")

expect.type<{ encrypted: Buffer, key: Iron.Key }>(await Iron.encrypt(password, options, "hello"))
expect.type<{ encrypted: Buffer, key: Iron.Key }>(await Iron.encrypt(buffer, options, "hello"))

expect.error(Iron.encrypt(256, options, "hello"))
expect.error(Iron.encrypt({ foo: "bar" }, options, "hello"))
expect.error(Iron.encrypt(password, { foo: "bar" }, "hello"))
expect.error(Iron.encrypt(password, options))


// decrypt()

Iron.decrypt(password, options, "uuddlrlrbabas")
Iron.decrypt(buffer, options, "uuddlrlrbabas")

expect.type<string>(await Iron.decrypt(password, options, "uuddlrlrbabas"))
expect.type<string>(await Iron.decrypt(buffer, options, "uuddlrlrbabas"))

expect.error(Iron.decrypt(256, options, "uuddlrlrbabas"))
expect.error(Iron.decrypt({ foo: "bar" }, options, "uuddlrlrbabas"))
expect.error(Iron.decrypt(256, { foo: "bar" }, "uuddlrlrbabas"))
expect.error(Iron.decrypt(password, options))


// hmacWithPassword()

Iron.hmacWithPassword(password, options, 'some_string')
Iron.hmacWithPassword(buffer, options, 'some_string')

expect.type<{ digest: string, salt: string }>(await Iron.hmacWithPassword(password, options, 'some_string'))
expect.type<{ digest: string, salt: string }>(await Iron.hmacWithPassword(buffer, options, 'some_string'))

expect.error(Iron.hmacWithPassword(256, options, 'some_string'))
expect.error(Iron.hmacWithPassword({ foo: "bar" }, options, 'some_string'))
expect.error(Iron.hmacWithPassword(password, { foo: "bar" }, 'some_string'))
expect.error(Iron.hmacWithPassword(password, options, 256))
expect.error(Iron.hmacWithPassword(password, options))


// seal()

Iron.seal('seal_this_string', password, defaults)
Iron.seal(true, password, defaults)
Iron.seal(options, password, defaults)
Iron.seal(256, password, defaults)
Iron.seal(["a", 1, true], password, defaults)
Iron.seal(["a", 1, true], buffer, defaults)

expect.type<string>(await Iron.seal('seal_this_string', password, defaults))
expect.type<string>(await Iron.seal('seal_this_string', buffer, defaults))

expect.error(Iron.seal('seal_this_string', 256, defaults))
expect.error(Iron.seal('seal_this_string', password, options))
expect.error(Iron.seal(null, { foo: "bar" }, defaults))
expect.error(Iron.seal('seal_this_string', password))


// unseal()

Iron.unseal('uuddlrlrbabas', password, defaults)
Iron.unseal('uuddlrlrbabas', buffer, defaults)

expect.type<object>(await Iron.unseal('uuddlrlrbabas', password, defaults))
expect.type<object>(await Iron.unseal('uuddlrlrbabas', buffer, defaults))

expect.error(Iron.unseal(256, password, defaults))
expect.error(Iron.unseal('uuddlrlrbabas', password, options))
expect.error(Iron.unseal('uuddlrlrbabas', 256, defaults))
expect.error(Iron.unseal(256, password))

// Key derivation test.
QUnit.asyncTest('deriveKey', function(assert) {
	'use strict';
	var passphrase = 'This passphrase is supposed to be good enough for miniLock. :-)'
	var knownSalt = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16])
	miniLock.crypto.getKeyPair(passphrase)
	assert.deepEqual(miniLock.session.keyPairReady, false, 'keyPairReady starts as false')
	assert.deepEqual(Object.keys(miniLock.session.keys).length, 0, 'sessionKeys is empty')
	var keyInterval = setInterval(function() {
		if (miniLock.session.keyPairReady) {
			clearInterval(keyInterval)
			assert.deepEqual(Object.keys(miniLock.session.keys).length, 2, 'sessionKeys is filled')
			assert.deepEqual(miniLock.session.keyPairReady, true, 'keyPairReady set to true')
			assert.deepEqual(typeof(miniLock.session.keys), 'object', 'Type check')
			assert.deepEqual(typeof(miniLock.session.keys.publicKey), 'object', 'Public key type check')
			assert.deepEqual(typeof(miniLock.session.keys.secretKey), 'object', 'Secret key type check')
			assert.deepEqual(miniLock.session.keys.publicKey.length, 32, 'Public key length')
			assert.deepEqual(miniLock.session.keys.secretKey.length, 32, 'Secret key length')
			assert.deepEqual(typeof(miniLock.session.baseKey), 'object', 'Unsalted base key set')
			assert.deepEqual(miniLock.session.baseKey.length, 64, 'Unsalted base key length')
			assert.deepEqual(typeof(miniLock.session.salt), 'object', 'Session salt set')
			assert.deepEqual(miniLock.session.salt.length, 16, 'Session salt length')

			//set a known salt
			/*jshint -W106 */
			var scrypt = scrypt_module_factory()
			var testKeyBytes = scrypt.crypto_scrypt(
				miniLock.session.baseKey,
				knownSalt,
				Math.pow(2, 17), 8, 1, 32
			)
			/*jshint +W106 */
			var testKeyPair = nacl.box.keyPair.fromSecretKey(testKeyBytes)
			assert.deepEqual(
				Base58.encode(testKeyPair.publicKey),
				'FinDjPvtMhLykeAQwjFaFjp7356v32BLLqfzqh4AKb5g',
				'Public key Base58 representation'
			)
			assert.deepEqual(
				nacl.util.encodeBase64(testKeyPair.secretKey),
				'rPnWH9OcnUpFs7q5H/VBTU+9C6r69bkbhSdXPtvCdsQ=',
				'Secret key Base64 representation'
			)
			assert.deepEqual(
				miniLock.crypto.getMiniLockID(testKeyPair.publicKey, knownSalt),
				'92Lf9hFHdVuXLgru4UGf5TbHFettdwNCwCpeHRUVnwhaJN64x7LBUvi7gANj2Hr51y',
				'miniLock ID from public key'
			)
			QUnit.start()
		}
	}, 500)
})

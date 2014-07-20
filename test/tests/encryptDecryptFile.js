// Test for file encryption.
QUnit.asyncTest('encryptDecryptFile', function(assert) {
	'use strict';
	var xhr = new XMLHttpRequest()
	xhr.open('GET', 'files/test.jpg', true)
	xhr.responseType = 'blob'
	xhr.onload = function() {
		var blob = this.response
		miniLock.file.get(blob, function(result) {
			result.name = 'test.jpg'
			assert.deepEqual(result.size, 348291, 'Original file size')
			miniLock.crypto.encryptFile(
				result,
				result.name,
				[
					'3HCvcCakcWCSeY1NkNxSmZMGAm8BJ7hencUTXUDH3PKVWHPJuCW8vUGf1BNBF7wTrP',
					'w7ZKkzB3kyjjbyuiuFXP5TDTC35i54MDXwwzN7mSU3mfVEhLDZzgjzCYZJ9DRi4aX'
				],
				Base58.decode('2iHTmqFtKEK5Xd3fi6sd5VguwCP3MeejFvBmazL8327m'),
				Base58.decode('815vjksSb41chLWJVXBn3jYiPW9H1qs3AxEtugqWDEzC'),
				Base58.decode('79S6JKbUEKDWApQuf7KssZ'),
				'miniLock.test.encryptFileCallback'
			)
		})
	}
	xhr.send()
	miniLock.test.encryptFileCallback = function(message) {
		assert.deepEqual(message.name, 'test.jpg', 'Original file name')
		assert.deepEqual(message.saveName, 'test.jpg.minilock', 'Encrypted file name')
		assert.deepEqual(message.blob.size, 352956, 'Encrypted file size')
		miniLock.file.get(message.blob, function(result) {
			result.name = 'userHasChangedTheName.minilock'
			miniLock.crypto.decryptFile(
				result,
				Base58.decode('2iHTmqFtKEK5Xd3fi6sd5VguwCP3MeejFvBmazL8327m'),
				Base58.decode('3jKVcp6Xp3CmHsYowcfpRZ3Cn1kLVokFu1zfKM6DMHmfmdkXBTALz715gxJdeQEKmKzAqKLw4TvCc8mFVhRNK5of'),
				'miniLock.test.decryptFileCallback'
			)
		})
	}
	miniLock.test.decryptFileCallback = function(message) {
		var reader = new FileReader()
		assert.deepEqual(message.name, 'test.jpg', 'Decrypted file name')
		assert.deepEqual(message.blob.size, 348291, 'Decrypted file size')
		reader.onload = function() {
			var hash = nacl.hash(new Uint8Array(this.result))
			assert.deepEqual(
				nacl.util.encodeBase64(hash),
				'NT2406X+QT6rIvmK9lsDGWuiljvWAd5S+IoEh7suxiVE+S//lmCU/Q3mDFWFeqNRdWjqvTSVEqRg3oZB++wYzg==',
				'Decrypted file integrity'
			)
			QUnit.start()
		}
		reader.readAsArrayBuffer(message.blob)
	}
})

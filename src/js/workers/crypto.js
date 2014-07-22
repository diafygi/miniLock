// -----------------------
// Initialization
// -----------------------

/*jshint -W079 */
var window = {}
/*jshint +W079 */
importScripts(
	'../lib/crypto/nacl.js',
	'../lib/crypto/scrypt.js',
	'../lib/indexOfMulti.js',
	'../lib/base58.js'
)
var nacl = window.nacl

// -----------------------
// Utility functions
// -----------------------

var base64Match = new RegExp(
	'^(?:[A-Za-z0-9+\/]{4})*(?:[A-Za-z0-9+\/]{2}==|[A-Za-z0-9+\/]{3}=)?$'
)

var base58Match = new RegExp(
	'^[1-9ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]+$'
)

// Input: String
// Output: Boolean
// Notes: Validates if string is a proper miniLock ID.
var validateID = function(id) {
	if (
		(id.length > 70) ||
		(id.length < 60)
	) {
		return false
	}
	if (base58Match.test(id)) {
		var bytes = Base58.decode(id)
		return bytes.length === 32 + 16
	}
	return false
}

// Input: String
// Output: Boolean
// Notes: Validates if string is a proper nonce.
var validateNonce = function(nonce) {
	if (
		(nonce.length > 40) ||
		(nonce.length < 10)
	) {
		return false
	}
	if (base64Match.test(nonce)) {
		var bytes = nacl.util.decodeBase64(nonce)
		return bytes.length === 24
	}
	return false
}

// Input: String
// Output: Boolean
// Notes: Validates if string is a proper symmetric key.
var validateKey = function(key) {
	if (
		(key.length > 50) ||
		(key.length < 40)
	) {
		return false
	}
	if (base64Match.test(key)) {
		var bytes = nacl.util.decodeBase64(key)
		return bytes.length === 32
	}
	return false
}

var validateEphemeral = validateKey

// Input:
//	publicKey: my public key (Uint8Array)
//	salt: Session salt (Uint8Array)
// Output: miniLockID (Base58)
// Notes: Combines session salt and public key into one Base58 string
var encodeID = function(publicKey, salt) {
	var tmpID = new Uint8Array(publicKey.byteLength + salt.byteLength)
	tmpID.set(new Uint8Array(publicKey), 0)
	tmpID.set(new Uint8Array(salt), publicKey.byteLength)
	return Base58.encode(tmpID)
}

// Input: miniLockID (Base58)
// Output: Object: {
//	publicKey: public key (Uint8Array),
//	salt: Session salt (Uint8Array),
// }
// Notes: Breaks up the miniLockID into the public key and salt components
var decodeID = function(miniLockID) {
	var tmpID = Base58.decode(miniLockID)
	var keyLength = tmpID.byteLength - 16
	var publicKey = tmpID.subarray(0, keyLength)
	var salt = tmpID.subarray(keyLength, tmpID.byteLength)
	return {
		publicKey: publicKey,
		salt: salt
	}
}

// Input:
//	baseKey (Uint8Array)
//	salt (Uint8Array)
// Output: secretKey (Uint8Array)
// Notes: Salts and hashes using scrypt without a web worker (since this is
//	already a worker)
var inlineScrypt = function(baseKey, salt) {
	/*jshint -W106 */
	var scrypt = scrypt_module_factory()
	return scrypt.crypto_scrypt(baseKey, salt, Math.pow(2, 17), 8, 1, 32)
	/*jshint +W106 */
}

// -----------------------
// Cryptographic functions
// -----------------------

// Receive a message to perform a certain operation.
// Input: Object:
//	{
//		operation: Type of operation ('encrypt' or 'decrypt'),
//		data: Data to encrypt/decrypt (Uint8Array),
//		name: File name (String),
//		saveName: Name to use for saving resulting file (String),
//		fileKey: 32-byte key used for file encryption (Uint8Array),
//		fileNonce: 24-byte nonce used for file encryption/decryption (Uint8Array),
//		fileInfoNonces: Array of 24-byte nonces (Uint8Array) to be used to encrypt fileInfo objects (one for each recipient),
//		fileKeyNonces: Array of 24-byte nonces (Uint8Array) to be used to encrypt fileKey to recipients (one for each recipient),
//		fileNameNonces: Array of 24-byte nonces (Uint8Array) to be used to encrypt fileName to recipients (one for each recipient),
//		ephemeral: {
//			publicKey: Ephemeral Curve25519 public key (Uint8Array),
//			secretKey: Ephemeral Curve25519 secret key (Uint8Array)
//		} (Only used for encryption)
//		publicKeys: Array of (Base58) public keys to encrypt to (not used for 'decrypt' operation),
//		myPublicKey: My public key (Uint8Array),
//		mySecretKey: My secret key (Uint8Array),
//		salt: Session salt (Uint8Array)
//	}
// Result: When finished, the worker will return the result
// 	which is supposed to be caught and processed by
//	the miniLock.crypto.worker.onmessage() function
//	in miniLock.js.
// Notes: A miniLock-encrypted file's first 16 bytes are always the following:
//	0x6d, 0x69, 0x6e, 0x69,
//	0x4c, 0x6f, 0x63, 0x6b,
//	0x46, 0x69, 0x6c, 0x65,
//	0x59, 0x65, 0x73, 0x2e
//	Those 16 bytes are then followed by the following JSON object (binary-encoded):
//	{
//		ephemeral: Public key from ephemeral key pair used to encrypt fileInfo object (Base64),
//		fileInfo: {
//			(One copy of the below object for every recipient)
//			Unique nonce for decrypting this object (Base64): {
//				fileKey: {
//					data: Key for file decryption, encrypted using long-term key pair (Base64),
//					nonce: Nonce for above (Base64)
//				}
//				fileName: {
//					data: The file's original filename, encrypted using long-term key pair (Base64),
//					nonce: Nonce for above (Base64)
//				}
//				fileNonce: Nonce for file decryption (Base64),
//				senderID: Sender's miniLock ID (Base58)
//			}
//			(Encrypted with recipient's public key using ephemeral key pair and stored as Base64 string)
//		}
//	}
// Note that the file name is padded with 0x00 bytes until it reaches 256 bytes in length.
//	The JSON object's end is then signaled by the following 16-byte delimiter:
//		0x6d, 0x69, 0x6e, 0x69,
//		0x4c, 0x6f, 0x63, 0x6b,
//		0x45, 0x6e, 0x64, 0x49,
//		0x6e, 0x66, 0x6f, 0x2e
//	...after which we have the ciphertext in binary format.
//	Note that we cannot ensure the integrity of senderID unless it can be used to carry out a
//	successful, authenticated decryption of both fileInfo and consequently the ciphertext.
onmessage = function(message) {
message = message.data

// We have received a request to encrypt
if (message.operation === 'encrypt') {
	(function() {
		var header = {
			ephemeral: nacl.util.encodeBase64(message.ephemeral.publicKey),
			fileInfo: {}
		}
		var paddedFileName = message.name
		while (paddedFileName < 256) {
			paddedFileName += String.fromCharCode(0x00)
		}
		for (var i = 0; i < message.miniLockIDs.length; i++) {
			var decodedMiniLockID = decodeID(message.miniLockIDs[i])
			var encryptedFileKey = nacl.box(
				message.fileKey,
				message.fileKeyNonces[i],
				decodedMiniLockID.publicKey,
				message.mySecretKey
			)
			var encryptedFileName = nacl.box(
				nacl.util.decodeUTF8(paddedFileName),
				message.fileNameNonces[i],
				decodedMiniLockID.publicKey,
				message.mySecretKey
			)
			var fileInfo = {
				senderID: encodeID(message.myPublicKey, message.salt),
				fileKey: {
					data: nacl.util.encodeBase64(encryptedFileKey),
					nonce: nacl.util.encodeBase64(message.fileKeyNonces[i])
				},
				fileName: {
					data: nacl.util.encodeBase64(encryptedFileName),
					nonce: nacl.util.encodeBase64(message.fileNameNonces[i])
				},
				fileNonce: nacl.util.encodeBase64(message.fileNonce)
			}
			fileInfo = JSON.stringify(fileInfo)
			var encryptedFileInfo = nacl.box(
				nacl.util.decodeUTF8(fileInfo),
				message.fileInfoNonces[i],
				decodedMiniLockID.publicKey,
				message.ephemeral.secretKey
			)
			header.fileInfo[
				nacl.util.encodeBase64(message.fileInfoNonces[i])
			] = {
				encHeader: nacl.util.encodeBase64(encryptedFileInfo),
				salt: nacl.util.encodeBase64(decodedMiniLockID.salt)
			}
		}
		var encrypted = nacl.secretbox(
			message.data,
			message.fileNonce,
			message.fileKey
		)
		if (!encrypted) {
			postMessage({
				operation: 'encrypt',
				error: true
			})
			throw new Error('miniLock: Encryption failed - general encryption error')
			return false
		}
		postMessage({
			operation: 'encrypt',
			data: encrypted,
			name: message.name,
			saveName: message.saveName,
			header: header,
			senderID: encodeID(message.myPublicKey, message.salt),
			error: false,
			callback: message.callback
		})
	})()
}


// We have received a request to decrypt
if (message.operation === 'decrypt') {
	(function() {
		var miniLockInfoEnd = [
			0x6d, 0x69, 0x6e, 0x69,
			0x4c, 0x6f, 0x63, 0x6b,
			0x45, 0x6e, 0x64, 0x49,
			0x6e, 0x66, 0x6f, 0x2e
		]
		var miniLockInfoEndIndex, header
		try {
			miniLockInfoEndIndex = message.data.indexOfMulti(miniLockInfoEnd)
			header = nacl.util.encodeUTF8(message.data.subarray(16, miniLockInfoEndIndex))
			header = JSON.parse(header)
			message.data = message.data.subarray(
				miniLockInfoEndIndex + miniLockInfoEnd.length,
				message.data.length
			)
		}
		catch(error) {
			postMessage({
				operation: 'decrypt',
				error: true
			})
			throw new Error('miniLock: Decryption failed - could not parse file header')
			return false
		}
		if (
			!header.hasOwnProperty('ephemeral')
			|| !validateEphemeral(header.ephemeral)
		) {
			postMessage({
				operation: 'decrypt',
				error: true
			})
			throw new Error('miniLock: Decryption failed - could not validate sender ID')
			return false
		}
		// Attempt fileInfo decryptions until one succeeds
		var actualFileInfo = false
		var actualFileKey  = false
		var actualFileName = false
		var testKeyBytes = false
		for (var i in header.fileInfo) {
			if (
				({}).hasOwnProperty.call(header.fileInfo, i)
				&& validateNonce(i)
			) {
				try {
					nacl.util.decodeBase64(header.fileInfo[i].encHeader)
				}
				catch(err) {
					postMessage({
						operation: 'decrypt',
						error: true
					})
					throw new Error('miniLock: Decryption failed - could not parse file header')
					return false
				}
				//use the salt to generate the test keyPair
				testKeyBytes = inlineScrypt(
					message.baseKey,
					nacl.util.decodeBase64(header.fileInfo[i].salt)
				)
				actualFileInfo = nacl.box.open(
					nacl.util.decodeBase64(header.fileInfo[i].encHeader),
					nacl.util.decodeBase64(i),
					nacl.util.decodeBase64(header.ephemeral),
					testKeyBytes
				)
				if (actualFileInfo) {
					try {
						actualFileInfo = JSON.parse(
							nacl.util.encodeUTF8(actualFileInfo)
						)
					}
					catch(err) {
						postMessage({
							operation: 'decrypt',
							error: true
						})
						throw new Error('miniLock: Decryption failed - could not parse file header')
						return false
					}
					break
				}
			}
		}
		if (
			!actualFileInfo
			|| !({}).hasOwnProperty.call(actualFileInfo, 'fileKey')
			|| !({}).hasOwnProperty.call(actualFileInfo.fileKey, 'data')
			|| !actualFileInfo.fileKey.data.length
			|| !({}).hasOwnProperty.call(actualFileInfo.fileKey, 'nonce')
			|| !validateNonce(actualFileInfo.fileKey.nonce)
			|| !({}).hasOwnProperty.call(actualFileInfo, 'fileName')
			|| !({}).hasOwnProperty.call(actualFileInfo.fileName, 'data')
			|| !actualFileInfo.fileName.data.length
			|| !({}).hasOwnProperty.call(actualFileInfo.fileName, 'nonce')
			|| !validateNonce(actualFileInfo.fileName.nonce)
			|| !({}).hasOwnProperty.call(actualFileInfo, 'fileNonce')
			|| !validateNonce(actualFileInfo.fileNonce)
			|| !({}).hasOwnProperty.call(actualFileInfo, 'senderID')
			|| !validateID(actualFileInfo.senderID)
		) {
			postMessage({
				operation: 'decrypt',
				error: true
			})
			throw new Error('miniLock: Decryption failed - could not parse file header')
			return false
		}
		try {
			actualFileKey = nacl.box.open(
				nacl.util.decodeBase64(actualFileInfo.fileKey.data),
				nacl.util.decodeBase64(actualFileInfo.fileKey.nonce),
				decodeID(actualFileInfo.senderID).publicKey,
				testKeyBytes
			)
			actualFileName = nacl.box.open(
				nacl.util.decodeBase64(actualFileInfo.fileName.data),
				nacl.util.decodeBase64(actualFileInfo.fileName.nonce),
				decodeID(actualFileInfo.senderID).publicKey,
				testKeyBytes
			)
			actualFileName = nacl.util.encodeUTF8(actualFileName)
		}
		catch(err) {
			postMessage({
				operation: 'decrypt',
				error: true
			})
			throw new Error('miniLock: Decryption failed - could not decrypt fileKey or fileName')
			return false
		}
		if (!actualFileKey || !actualFileName) {
			postMessage({
				operation: 'decrypt',
				error: true
			})
			throw new Error('miniLock: Decryption failed - could not decrypt fileKey or fileName')
			return false
		}
		while (
			actualFileName[
				actualFileName.length - 1
			] === String.fromCharCode(0x00)
		) {
			actualFileName = actualFileName.slice(0, -1)
		}
		var decrypted = nacl.secretbox.open(
			message.data,
			nacl.util.decodeBase64(actualFileInfo.fileNonce),
			actualFileKey
		)
		if (!decrypted) {
			postMessage({
				operation: 'decrypt',
				error: true
			})
			throw new Error('miniLock: Decryption failed - general decryption error')
			return false
		}
		postMessage({
			operation: 'decrypt',
			data: decrypted,
			name: actualFileName,
			saveName: actualFileName,
			senderID: actualFileInfo.senderID,
			error: false,
			callback: message.callback
		})
	})()
}

}

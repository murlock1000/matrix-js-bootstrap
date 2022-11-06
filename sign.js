global.Olm = require('olm');
const sdk = require('matrix-js-sdk');

const { deriveKey, keyFromAuthData } = require('matrix-js-sdk/lib/crypto/key_passphrase');
const { decodeRecoveryKey } = require('matrix-js-sdk/lib/crypto/recoverykey');
const { decodeBase64 } = require('matrix-js-sdk/lib/crypto/olmlib');
const { Method, PREFIX_UNSTABLE } = require('matrix-js-sdk/lib/http-api');
const { CrossSigningInfo } = require('matrix-js-sdk/lib/crypto/CrossSigning');

const { LocalStorage } = require('node-localstorage');
const localStorage =  new LocalStorage('./store');

let matrixClient;

// Disable logging
console.log = function(){};
console.warning = function(){};
console.info = function(){};
console.warn = function(){};
console.scriptout = function (d) {
	process.stdout.write(d + '\n');
};

// Import config with homeserver URL and domain
const config = require('./config.js')

// Parse CLI arguments
const argv = require('minimist')(process.argv.slice(2));
if(argv.u && argv.p && (argv.r || argv.k)) {
	config.user_id = '@'+argv.u+':'+config.domain;
	config.user_password = argv.p;
    if(argv.r){
	    config.passphrase = argv.r;
    }else{
        config.recoveryKey = argv.k;
    }
	initApp();
}else{
	console.scriptout("Usage: node sign.js -u <username> -p <password> { -r <recovery passphrase> | -k <recovery key> }");
}



async function getSecretStorageKey(keyInfos){
    //console.scriptout(JSON.stringify(keyInfos, null, 2));

    // Fetch the default secret storage key id from server.
    let keyId = await matrixClient.getDefaultSecretStorageKeyId(); 

    if (keyId){
        let keyInfo = keyInfos.keys[keyId];
        if (!keyInfo) {
            // if Secret storage default key info is not available (Initialised SSSS not uploaded to server?).
            throw new Error("SSSS does not contain the default key info. Has it been bootstrapped?");
        }else{
            let key = null;
            if(config.passphrase){

                // Construct the IAuthData type (with default private_key_bits).
                const authData = {
                    "private_key_salt": keyInfo.passphrase.salt,
                    "private_key_iterations": keyInfo.passphrase.iterations
                };

                // Derive the key bits using the passphrase.
                key = await keyFromAuthData(authData, config.passphrase);

                // One gotcha: key derivation from passphrase returns 256 bytes, but specification only uses 32!
                key = new Uint8Array(key);
                key = key.subarray(0,32);

            }else if(config.recoveryKey){
                // If recovery key passed - decode it.
                key = decodeRecoveryKey(config.recoveryKey);
            }
            // (DEBUG) console.scriptout(JSON.stringify(key, null, 2));
            return [keyId, key];
        }
    }else{
        // Could not find default key in Secret storage. Create one?
        throw new Error("SSSS does not contain the default key. Has it been bootstrapped?");
    }
}


// Calling the sdk built-in method <matrixClient.createKeyBackupVersion(backupInfo)> of creating/updating the key backup version is fine,
// but it additionally signs the backupInfo with this devices keys for backwards compatibility.
// We don't want that, since this would clutter the SB signature list with no longer existing devices (We destroy this device after we're finished).
// This rewritten method signs the backup only with the master cross signing key and uploads the new version.
async function createKeyBackupVersion(info){
    await matrixClient.crypto.backupManager.createKeyBackupVersion(info);

    const data = {
        algorithm: info.algorithm,
        auth_data: info.auth_data,
    };

    // now sign the auth data with the cross-signing master key
    try{
        await matrixClient.crypto.crossSigningInfo.signObject(data.auth_data, "master");
    }catch (e){
        // Usually we are using the wrong/encrypted/failed to decrypt key.
        throw e;
    }

    const res = await matrixClient.http.authedRequest(
        undefined, Method.Post, "/room_keys/version", undefined, data,
        { prefix: PREFIX_UNSTABLE },
    );

    // We could assume everything's okay and enable directly, but this ensures
    // we run the same signature verification that will be used for future
    // sessions.
    await matrixClient.checkKeyBackup();
    if (!matrixClient.getKeyBackupEnabled()) {
        logger.error("Key backup not usable even though we just created it");
    }

    return res;
}

async function initApp(){

	// Initialize the OLM (cryptographic) library
	await global.Olm.init();

	// Log in and retrieve the new device ID and session key
	const registerMatrixClient = sdk.createClient(config.homeserver_url);
	let userRegisterResult = await registerMatrixClient.loginWithPassword(config.user_id, config.user_password);

	// Initialize a MatrixClient instance using the retrieved authorization data.
	matrixClient = sdk.createClient({
		baseUrl: config.homeserver_url,
		userId: userRegisterResult.user_id,
		accessToken: userRegisterResult.access_token,
		deviceId: userRegisterResult.device_id,
		sessionStore: new sdk.WebStorageSessionStore(localStorage),
		cryptoStore: new sdk.MemoryCryptoStore(),
	  });

	// Get information about the user
	let uinfo = await matrixClient.whoami();
	console.scriptout("Recovering Cross-signing keys and signing SSSS for: "+uinfo.user_id+" from device ID: "+uinfo.device_id);
	
    // Set our own custom getSecretStorageKey callback for fetching the default SSSS key from server.
    // It also decrypts the key using a passphrase or recovery key.
    // We must set this before initialising crypto, 
    // since it allows the crypto constructor to create the default cryptoCallbacks.getCrossSigningKey callback from (SSSS) if we (the app) do not provide our own.
    matrixClient.cryptoCallbacks.getSecretStorageKey = getSecretStorageKey;

	// Initializing crypto creates a new Olm device and 
	// generates device keys (Ed25519 fingerprint key pair and Curve25519 identity key pair)
	await matrixClient.initCrypto();

    // Set the getCrossSigningKey callback to return the key from SSSS (We assume the keys have been uploaded to server before).
    // This was already set by the crypto constructor to CrossSigningInfo.getFromSecretStorage.
    // However, I am rewriting it here with validation so we can check the extracted public parts outside the sdk (does not log them).

    matrixClient.cryptoCallbacks.getCrossSigningKey = async (type, expectedPubkey) => {

        function validateKey(key){
            if (!key) return;
            const signing = new global.Olm.PkSigning();
            const gotPubkey = signing.init_with_seed(key);
            if (gotPubkey === expectedPubkey) {
                return [gotPubkey, signing];
            }else{
                // We got some keys from the keysource, but none of them were valid.
                signing.free();
                throw new Error(
                    "Key type " + type + " from getCrossSigningKey callback did not match. Expected pub: "+expectedPubkey+ " Received: "+gotPubkey,
                );
            }
        }

        // Fetch the cross signing key of corresponding type (master, self_signing, user_signing) from Secret storage.
        const encodedKey = await matrixClient.crypto.secretStorage.get(`m.cross_signing.${type}`);
        if (!encodedKey) {
            return null;
        }
        validateKey(decodeBase64(encodedKey));
        return decodeBase64(encodedKey);
    };

    /// (DEBUG) Code for manually outputting the decrypted SSSS default key to console.
    //let key = await matrixClient.crypto.getSecretStorageKey();
    //let m = {'keys':{}}
    //m['keys'][key[0]] = key[1]
    //let v = await matrixClient.cryptoCallbacks.getSecretStorageKey(m)
    //console.scriptout(JSON.stringify(v, null, 2));


    // Instead of doing everything - we only perform the steps required to fetch and cache Cross signing keys. 
    // Trimmed down code taken from: matrixClient.crypto.checkOwnCrossSigningTrust(false); 

    let userId = matrixClient.getUserId();
    // Fetch the keys for our device. This populates the matrixClient.deviceList
    await matrixClient.downloadKeys([userId]);
     // First, get the new cross-signing info
    const newCrossSigning = matrixClient.crypto.deviceList.getStoredCrossSigningForUser(userId);

    if (!newCrossSigning) {
        console.scriptout(
            "Got cross-signing update event for user " + userId +
            " but no new cross-signing information found!",
        );
        await matrixClient.logout();
        return;
    }

    // Store the decrypted (?) cross signing keys to memory.
    matrixClient.crypto.storeTrustedSelfKeys(newCrossSigning.keys);

    // Steps for signing the backupInfo with master key manually.
    // 1. Fetch the latest backup info: const backupInfo = await matrixClient.getKeyBackupVersion();
    // 2. Sign it with the master key: let signed_auth = await matrixClient.crypto.crossSigningInfo.signObject(backupInfo.auth_data, "master");
    
    // Fetch the information about the current SSSS.
    const backupInfo = await matrixClient.getKeyBackupVersion();

    // This works, but also signs with the device: await matrixClient.createKeyBackupVersion(backupInfo);
    let res;
    try{
        res = await createKeyBackupVersion(backupInfo);
    }catch(e){
        console.scriptout(e);
        await matrixClient.logout();
        return;
    }
    console.scriptout("Successfully signed the SB with a master key. The incremented SB version: "+res.version);
    await matrixClient.logout();
}
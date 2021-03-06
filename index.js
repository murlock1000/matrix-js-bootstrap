global.Olm = require('olm');
var sdk = require('matrix-js-sdk');
var LocalStorage = require('node-localstorage');

const enc = new TextEncoder();
var localStorage =  new LocalStorage.LocalStorage('./store');

const config ={
	"passphrase":"VERYSECUREPASSPHRASE",
	"user_id": "@user:matrix.synapse",
  	"user_password": "password",
  	"homeserver_url": "http://localhost:8008"
}

async function initApp(){

	// Initialize the OLM (cryptographic) library
	await global.Olm.init();

	// Log in and retrieve the new device ID and session key
	const registerMatrixClient = sdk.createClient(config.homeserver_url);
	let userRegisterResult = await registerMatrixClient.loginWithPassword(config.user_id, config.user_password);

	// Initialize a MatrixClient instance using the retrieved authorization data.
	const matrixClient = sdk.createClient({
		baseUrl: config.homeserver_url,
		userId: userRegisterResult.user_id,
		accessToken: userRegisterResult.access_token,
		deviceId: userRegisterResult.device_id,
		sessionStore: new sdk.WebStorageSessionStore(localStorage),
		cryptoStore: new sdk.MemoryCryptoStore(),
	  });

	// Get information about the user
	let uinfo = await matrixClient.whoami();
	console.log("Bootstrapping user: "+uinfo.user_id+" with device ID: "+uinfo.device_id);
	

	// Initializing crypto creates a new Olm device and 
	// generates device keys (Ed25519 fingerprint key pair and Curve25519 identity key pair)
	await matrixClient.initCrypto();

	// Cross-signing allows us to verify devices with a single common master key, instead of using a verified device instance.
	// https://matrix.org/docs/guides/implementing-more-advanced-e-2-ee-features-such-as-cross-signing#general-ideas-of-cross-signing

	// Important note: the newly created cross-signing keys are not uploaded to account data (bug?).
	// This is currently performed when bootstrapping secret storage.
	await matrixClient.bootstrapCrossSigning({
		authUploadDeviceSigningKeys: async (makeRequest)=>{

			// Complying with the User-Interactive Authentication API of uploading device signing keys,
			// we first make a request without the auth parameter and retrieve the session id (as well as authentication flow data).
			// We use this session id to authenticate the API request the second time.
			makeRequest().then(()=>{throw new Error("Should never have arrived here with empty auth.");}, async (reason)=>{

				let response_data = reason.data;
				let auth_data = {
						"session": response_data.session,
						"type": "m.login.password",
						"user": config.user_id,
						"identifier": {
							"type": "m.id.user",
							"user": config.user_id
						},
						"password": config.user_password
				}
				makeRequest(auth_data).then(()=>{setupSecretStorage(matrixClient)}, (err)=>{throw new Error("Failed to upload device signing keys with error: "+err);});
			});
		},
		// Create new keys, even if ones already exist in secret storage.
		setupNewCrossSigning: true,
	  });
}

async function setupSecretStorage(matrixClient){

	const recoveryKey = matrixClient.createRecoveryKeyFromPassphrase(config.passphrase);

	// Setting up the secret storage:
	// Signs the SS key with cross-signing keys. 
	// This step also uploads cross-signing keys to account_data.
	await matrixClient.bootstrapSecretStorage({
		createSecretStorageKey: async () => recoveryKey,
		setupNewKeyBackup: true,
		setupNewSecretStorage: true,
	});

	recoveryKey.then(val =>{
		console.log("Encoded private key: "+val.encodedPrivateKey);
		console.log("Passphrase: "+config.passphrase);
	});
	// Lastly, upload device keys if not done already
	await matrixClient.uploadKeys();

	// Device session no longer needed - logout.
	await matrixClient.logout();
}

initApp();
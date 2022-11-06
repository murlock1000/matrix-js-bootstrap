# matrix-js-bootstrap
Provides detailed scripts for:
1. Bootstrapping the more advanced e2ee features: Cross-signing and SSSS (Secure Backup).
2. Fetching the Cross-signing keys from SSSS and decrypting them with a passphrase/backup key.
3. Signing the SSSS (Secure Backup) using the master Cross-Signing key.

# bootstrap.js
This script is used for generating new Cross-Signing keys (master, self_signing, user_signing). It then bootstraps a new SSSS instance on the server with a recovery (default) key generated from a provided recovery passphrase. The encrypted Cross-signing keys are then uploaded to the SSSS. The encoded recovery key is output through standard output. 

# sign.js
This script fetches the existing Cross-signing keys from the SSSS. It validates them with the key info stored in the users device list. The keys are decrypted using the provided passphrase/recovery key. The master key is then used to sign a new Secure Backup version. It skips signing the secure backup using the device.

# Project setup.

### Install curl
`sudo apt-get install curl`

### Install npm (V14)
`curl -sL https://deb.nodesource.com/setup_14.x | sudo -E bash -`

### Install nodejs
`sudo apt-get install nodejs`

### Clone project from git repository
`git clone https://github.com/murlock1000/matrix-js-bootstrap.git`

### Install dependencies
`npm install`

### Copy config.js file and edit it.
`cp sample.config.js config.js`

### Run project!
`node index.js -u <username> -p <password> -s <passphrase>`

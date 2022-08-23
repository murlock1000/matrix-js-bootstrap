# matrix-js-bootstrap
Bootstraps more advanced e2ee features, such as cross-signing and SSSS for a matrix user.

This script is used for generating a new Secure Secret Storage from a provided passphrase for a Matrix user. The encoded private key is printed out to the console and can be written down by the user or saved to a file. 

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

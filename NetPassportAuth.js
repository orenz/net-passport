const fs = require("fs");
const { createSign } = require("crypto");
const axios = require("axios").default;

class Auth {
	constructor() {
		this.URL = "https://netpassport.io/verifyMessage";
	}

	sign(message, { privateKey, pathToPrivateKey }) {
		try {
			const signer = createSign("RSA-SHA256");
			signer.update(JSON.stringify(message));
			signer.end();
			if (pathToPrivateKey) {
				privateKey = fs.readFileSync(pathToPrivateKey, { encoding: "utf-8" });
			}
			const signature = signer.sign({ key: privateKey }, "hex");
			return signature;
		} catch (error) {
			console.error(error.message);
		}
	}

	async verify(message, signature) {
		try {
			const { data } = await axios.post(this.URL, { message, signature });
			return data;
		} catch (error) {
			console.error(error.message);
		}
	}
}

module.exports = new Auth();

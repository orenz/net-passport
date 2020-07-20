const axios = require("axios").default;
const { sign } = require("jsonwebtoken");
const env = require("./config.json");

class Auth {
  constructor() {
    this.signUrl = env.SIGN_URL;
    this.verifySigUrl = env.VERIFY_SIG;
  }

  sign(message, privateKey) {
    if (typeof privateKey === "object") {
      const path = privateKey.privateKeyLocation;
      privateKey = require("fs").readFileSync(path, "utf-8");
    }
    try {
      const signature = sign(message, privateKey, {
        algorithm: "PS256",
      });
      return signature;
    } catch (error) {
      console.error(error.message);
    }
  }

  async verify(message, signature) {
    try {
      const { data } = await axios.post(this.verifySigUrl, {
        message,
        signature,
      });
      return data;
    } catch (error) {
      console.error(error.message);
    }
  }
}

module.exports = new Auth();

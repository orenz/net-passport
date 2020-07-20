const axios = require("axios").default;
const jwt = require("jsonwebtoken");
const env = require("./config.json");

class Auth {
  constructor() {
    this._signUrl = env.SIGN_URL;
    this._verifySigUrl = env.VERIFY_SIG;
  }

  sign(message, privateKey) {
    if (typeof privateKey === "object") {
      const path = privateKey.privateKeyLocation;
      privateKey = require("fs").readFileSync(path, "utf-8");
    }
    try {
      const signature = jwt.sign(message, privateKey, {
        algorithm: "PS256",
      });
      return signature;
    } catch (error) {
      console.error(error.message);
    }
  }

  async verify(message, signature) {
    try {
      const { data } = await axios.post(this._verifySigUrl, {
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

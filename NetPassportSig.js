const { createHash } = require("crypto");
const { default: axios } = require("axios");
const jwt = require("jsonwebtoken");
const env = require("./config.json");

class Signature {
  constructor() {
    this._signUrl = env.SIGN_URL;
    this._verifySigUrl = env.VERIFY_SIG;
    this.verify = this.verify.bind(this);
  }

  static md5(message) {
    return createHash("md5").update(JSON.stringify(message)).digest("hex");
  }

  sign(message, privateKey) {
    if (typeof privateKey !== "string")
      throw new Error("Private key must be of type string");
    if (privateKey.indexOf("-----BEGIN PRIVATE KEY-----") === -1) {
      privateKey = require("fs").readFileSync(privateKey, "utf-8");
    }
    try {
      const hash = Signature.md5(message);
      const signature = jwt.sign(hash, privateKey, {
        algorithm: "RS256",
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

module.exports = new Signature();

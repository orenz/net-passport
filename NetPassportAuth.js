const axios = require("axios").default;
const { sign } = require("jsonwebtoken");

class Auth {
  constructor() {
    this.URL = "https://dev.netpassport.io/signature/verify";
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
      const { data } = await axios.post(this.URL, { message, signature });
      return data;
    } catch (error) {
      console.error(error.message);
    }
  }
}

module.exports = new Auth();

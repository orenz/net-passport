const fs = require("fs");
const axios = require("axios").default;
const { sign, verify } = require("jsonwebtoken");

class Auth {
  constructor() {
    this.URL = "https://dev.netpassport.io/signature/verify";
  }

  sign(message, privateKey) {
    try {
      // if (pathToPrivateKey) {
      //   privateKey = fs.readFileSync(pathToPrivateKey, { encoding: "utf-8" });
      // }
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

const { default: axios } = require("axios");
const passport = require("passport");
const NetPassportStrategy = require("./NetPassport_Strategy");
const sig = require("./NetPassportSig");
const { validateParams } = require("./utils");

const env = require("./config.json");

let HAS_INITIATED = false;
let netPassportAuth;

function passportMiddleware(keys) {
  passport.use(getNetPassStrategy(keys));
  serializeUser();
  deserializeUser();
  return (req, res, next) => {
    passport.initialize()(req, res, () => {
      passport.session()(req, res, next);
    });
  };
}

function getNetPassStrategy({ client_id, client_secret, redirect_uri }) {
  return new NetPassportStrategy(
    {
      clientID: client_id,
      clientSecret: client_secret,
      callbackURL: redirect_uri,
    },
    function (accessToken, refreshToken, profile, done) {
      return done(null, profile);
    }
  );
}

function serializeUser() {
  passport.serializeUser(function (user, cb) {
    cb(null, user);
  });
}

function deserializeUser() {
  passport.deserializeUser(function (user, cb) {
    cb(null, user);
  });
}

class NetPassportAuth {
  constructor(privateKey, message) {
    this.privateKey = privateKey;
    this.message = message;
    this.verify = sig.verify;
    this.makeAuthentication = this.makeAuthentication.bind(this);
    this._URL = env.GENERATE_KEYS;
  }

  sign() {
    this.signature = sig.sign(this.message, this.privateKey);
  }

  async getOAuth2Keys() {
    try {
      const { data } = await axios.post(this._URL, {
        message: this.message,
        signature: this.signature,
      });
      return data;
    } catch (error) {
      throw new Error(
        error.response ? error.response.statusText : error.message
      );
    }
  }

  nextStep(req) {
    if (
      req.path === this.message.relativePath.initUri ||
      `${this.message.relativePath.initUri}/`
    ) {
      return "INIT_AUTH";
    }
    if (req.path === this.message.relativePath.redirectUri) {
      return "CALLBACK_AUTH";
    }
    return "NEXT";
  }

  passportAuth(action) {
    if (action === "INIT_AUTH") {
      return (req, res, next) =>
        passport.authenticate("net-passport")(req, res, next);
    }
    if (action === "CALLBACK_AUTH") {
      return (req, res, next) =>
        passport.authenticate("net-passport", {
          successRedirect: this.message.successRedirect,
          failureRedirect: this.message.failureRedirect,
        })(req, res, next);
    }
    return (req, res, next) => next();
  }

  async makeAuthentication(req, res, next) {
    if (!this.oauth2Keys) {
      this.oauth2Keys = await this.getOAuth2Keys();
    }
    const action = this.nextStep(req);
    passportMiddleware(this.oauth2Keys)(req, res, () => {
      this.passportAuth(action)(req, res, next);
    });
  }

  static getFullURI(req, message) {
    message.redirectUri =
      message.redirectUri.slice(-1) === "/"
        ? message.redirectUri
        : `${message.redirectUri}/`;

    message.relativePath = {
      initUri: message.initUri,
      redirectUri: message.redirectUri,
    };

    message.initUri = `${req.protocol}://${req.get("host")}${message.initUri}`;
    message.redirectUri = `${req.protocol}://${req.get("host")}${
      message.redirectUri
    }`;
  }
}

const authenticate = (privateKey, message) => {
  try {
    validateParams(privateKey, message);
  } catch (error) {
    return (req, res, next) => {
      console.log(error);
      next(error.message);
    };
  }
  return async (req, res, next) => {
    try {
      if (!HAS_INITIATED) {
        netPassportAuth = new NetPassportAuth(privateKey, message);
        NetPassportAuth.getFullURI(req, message);
        netPassportAuth.sign();
        HAS_INITIATED = true;
      }
      if (netPassportAuth) {
        await netPassportAuth.makeAuthentication(req, res, next);
      }
    } catch (error) {
      console.log("Error in NetPassport middleware: ", error);
      next(error);
    }
  };
};

module.exports = { authenticate };

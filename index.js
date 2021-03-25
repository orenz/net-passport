// const https = require("https");
const { default: axios } = require("axios");
const passport = require("passport");
const NetPassportStrategy = require("./NetPassport_Strategy");
const signer = require("./NetPassportSig");
const { validateParams } = require("./utils");

const env = require("./config.json");
// const agent = new https.Agent({ rejectUnauthorized: false });

let HAS_INITIATED = false;
let netPassportAuth;
let ERR = false;

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
  // gStrategy._oauth2.setAgent(new https.Agent({ rejectUnauthorized: false }));
  // passport.use(gStrategy);
  // return gStrategy;
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
    this.verify = signer.verify;
    this.makeAuthentication = this.makeAuthentication.bind(this);
    this._URL = env.GENERATE_KEYS;
  }

  sign() {
    this.signature = signer.sign(this.message, this.privateKey);
  }

  async getOAuth2Keys() {
    try {
      const { data } = await axios.post(
        this._URL,
        {
          message: this.message,
          signature: this.signature,
        },
        // { httpsAgent: agent }
      );
      return data;
    } catch (error) {
      console.log(
        "error getting oauth2 keys ",
        error.response ? error.response.data.message : error.message
      );
      ERR = true;
      return;
    }
  }

  nextStep(req) {
    if (
      (this.options && this.options.initUri) ||
      req.path === this.message.relativePath.initUri ||
      req.path === `${this.message.relativePath.initUri}/`
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
        passport.authenticate("net-passport", {
          userProperty: this.options.appName || this.message.appName
        })(req, res, next);
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
    if (ERR) {
      return next();
    }
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

    message.initUri = message.initUri
      ? `${req.protocol}://${req.get("host")}${message.initUri}`
      : null;
    message.redirectUri = `${req.protocol}://${req.get("host")}${message.redirectUri}`;
  }
}

const authenticate = (privateKey, message, options) => {
  try {
    validateParams(privateKey, message);
  } catch (error) {
    return (req, res, next) => {
      console.log("Error authenticate ", error);
      next();
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
        netPassportAuth.options = options;
        await netPassportAuth.makeAuthentication(req, res, next);
      }
    } catch (error) {
      console.log("Error in NetPassport middleware: ", error);
      next();
    }
  };
};

module.exports = { authenticate, signer };

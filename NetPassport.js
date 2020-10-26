/* eslint-disable no-underscore-dangle */
const axios = require("axios").default;
const passport = require("passport");
const auth = require("./NetPassportSig");
const NetPassportStrategy = require("./NetPassport_Strategy");
const env = require("./config.json");

class NetPassport {
  constructor() {
    this.authenticate = this.authenticate.bind(this);
    this._HAS_INITIATED = false;
    this._URL = env.GENERATE_KEYS;
    this.sign = auth.sign;
    this.verify = auth.verify;
  }

  authenticate(privateKey, message) {
    return async (req, res, next) => {
      if (!this._HAS_INITIATED) {
        this.message = message;
        NetPassport._getFullURI(req, this.message);
        this.signature = this.sign(this.message, privateKey);
        this._HAS_INITIATED = true;
      }
      await this.run(req, res, next);
    };
  }

  async run(req, res, next) {
    try {
      if (!this.oauth2Keys) {
        this.oauth2Keys = await this.getOAuth2Keys();
      }
      const action = this.authURI(req);
      passportMiddleware(this.oauth2Keys)(req, res, () => {
        this.passportAuth(action)(req, res, next);
      });
    } catch (error) {
      next(error);
    }
  }

  async getOAuth2Keys() {
    try {
      const { data } = await axios.post(this._URL, {
        message: this.message,
        signature: this.signature,
      });
      return data;
    } catch (error) {
      throw new Error(error.message);
    }
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

  authURI(req) {
    if (req.url === this.message.relativePath.initUri) {
      return "INIT_AUTH";
    }
    if (req.path === this.message.relativePath.redirectUri) {
      return "CALLBACK_AUTH";
    }
    return "NEXT";
  }

  callback({ successRedirect, failureRedirect }) {
    this.successRedirect = successRedirect;
    this.failureRedirect = failureRedirect;
    return async (req, res, next) => {
      await this.run(req, res, next);
    };
  }

  static _getFullURI(req, message) {
    // message.initUri =
    //   message.initUri.slice(-1) === "/"
    //     ? message.initUri
    //     : `${message.initUri}/`;
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

function passportMiddleware(keys) {
  passport.use(getNetPassStrategy(keys));
  serializeUser();
  deserializeUser();
  return function (req, res, next) {
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

module.exports.netPassport = new NetPassport();

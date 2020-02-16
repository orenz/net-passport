const axios = require("axios").default;
const passport = require("passport");
const auth = require("./NetPassportAuth");
const NetPassportStrategy = require("./NetPassport_Strategy");

class NetPassportCreateKeys {
	constructor() {
		this.authenticate = this.authenticate.bind(this);
		this.sign = auth.sign;
		this.verify = auth.verify;
		this.URL = "https://netpassport.io/generateAppKeys/serverGen";
		this.ALL_AFTER_PATH_REGEX = /http[s]*:\/\/[^\/]+(\/.+)/;
	}

	register(message, options) {
		this.message = message;
		this.message.redirectUri = NetPassportCreateKeys._getRedirectURI(this.message);
		this.signature = this.sign(this.message, options);
	}

	authenticate(message, options) {
		this.register(message, options);
		return async (req, res, next) => {
			try {
				if (!this.oauth2Keys) {
					this.oauth2Keys = await this.getOAuth2Keys();
				}
				initPassport(this.oauth2Keys)(req, res, () => {
					this.fullUri = req.protocol + "://" + req.get("host") + req.originalUrl;
					this.authURI(req)(req, res, next);
				});
			} catch (error) {
				next(error);
			}
		};
	}

	async getOAuth2Keys() {
		try {
			const { data } = await axios.post(this.URL, { message: this.message, signature: this.signature });
			return data;
		} catch (error) {
			throw new Error(error.message);
		}
	}

	authURI(req) {
		if (this.message.initURI === this.fullUri) {
			return (req, res, next) => passport.authenticate("net-passport")(req, res, next);
		}
		if (
			req.path === this.message.redirectUri.match(this.ALL_AFTER_PATH_REGEX)[1] ||
			req.path.slice(0, -1) === this.message.redirectUri.match(this.ALL_AFTER_PATH_REGEX)[1] ||
			req.path === "/callback/auth/"
		) {
			return (req, res, next) =>
				passport.authenticate("net-passport", { successRedirect: this.message.successRedirect, failureRedirect: this.message.failureRedirect })(
					req,
					res,
					next
				);
		}
		return (req, res, next) => next();
	}

	static _getRedirectURI(message) {
		return message.redirectUri || `${message.initURI}${message.initURI.slice(-1) === "/" ? "callback/auth" : "/callback/auth"}`;
	}
}

function initPassport(keys) {
	passport.use(getNetPassStrategy(keys));
	serializeUser(passport);
	deserializeUser(passport);
	return function(req, res, next) {
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
			callbackURL: redirect_uri
		},
		function(accessToken, refreshToken, profile, done) {
			return done(null, profile);
		}
	);
}

function serializeUser(passport) {
	passport.serializeUser(function(user, cb) {
		cb(null, user);
	});
}

function deserializeUser(passport) {
	passport.deserializeUser(function(user, cb) {
		cb(null, user);
	});
}

module.exports.NetPassport = new NetPassportCreateKeys();
module.exports.NetPassportStrategy = NetPassportStrategy;

/**
 * Module dependencies.
 */
var util = require("util"),
  OAuth2Strategy = require("passport-oauth2"),
  InternalOAuthError = require("passport-oauth2").InternalOAuthError;
const env = require("./config.json");

/**
 * `Strategy` constructor.
 *
 * The NetPassport authentication strategy authenticates requests by delegating to
 * NetPassport using the OAuth 2.0 protocol.
 *
 * Applications must supply a `verify` callback which accepts an `accessToken`,
 * `refreshToken` and service-specific `profile`, and then calls the `done`
 * callback supplying a `user`, which should be set to `false` if the
 * credentials are not valid.  If an exception occured, `err` should be set.
 *
 * Options:
 *   - `clientID`      your NetPassport application's client id
 *   - `clientSecret`  your NetPassport application's client secret
 *   - `callbackURL`   URL to which NetPassport will redirect the user after granting authorization
 *
 * Examples:
 *
 *     passport.use(new NetPassportStrategy({
 *         clientID: '123-456-789',
 *         clientSecret: 'shhh-its-a-secret'
 *         callbackURL: 'https://www.example.net/auth/NetPassport/callback'
 *       },
 *       function(accessToken, refreshToken, profile, done) {
 *         User.findOrCreate(..., function (err, user) {
 *           done(err, user);
 *         });
 *       }
 *     ));
 *
 * @param {Object} options
 * @param {Function} verify
 * @api public
 */
function Strategy(options, verify) {
  options = options || {};
  options.authorizationURL = options.authorizationURL || env.AUTHORIZATION_URL;
  options.tokenURL = options.tokenURL || env.TOKEN_URL;
  this.profileURL = env.PROFILE_URL;

  OAuth2Strategy.call(this, options, verify);
  this.name = "net-passport";
}

/**
 * Inherit from `OAuth2Strategy`.
 */
util.inherits(Strategy, OAuth2Strategy);

/**
 * Retrieve user profile from NetPassport.
 *
 * This function constructs a normalized profile, with the following properties:
 *
 *   - `provider`         always set to `NetPassport`
 *   - `id`               the user's NetPassport ID
 *   - `username`         the user's NetPassport username
 *   - `displayName`      the user's full name
 *
 * @param {String} accessToken
 * @param {Function} done
 * @api protected
 */
Strategy.prototype.userProfile = function (accessToken, done) {
  this._oauth2.get(this.profileURL, accessToken, (err, body, res) => {
    if (err) {
      return done(new InternalOAuthError("failed to fetch user profile", err));
    }

    try {
      const json = JSON.parse(body);
      const profile = json.map((rec) => ({
        provider: this.name,
        id: rec.id,
        name: {
          familyName: rec.last_name,
          givenName: rec.first_name,
        },
        username: rec.username,
        identifier: rec.identifier,
        photo: rec.photo,
      }));
      profile._raw = body;
      profile._json = json;

      done(null, profile);
    } catch (e) {
      done(e);
    }
  });
};

/**
 * Return extra NetPassport-specific parameters to be included in the authorization
 * request.
 *
 * @param {object} options
 * @return {object}
 * @access protected
 */
Strategy.prototype.authorizationParams = function (options) {
  const params = {};
  // if (options.accessType) {
  // 	params["access_type"] = options.accessType;
  // }
  // if (options.state) {
  // }
  params["state"] = options.state || Math.random().toString(36).substring(7);
  if (options.userProperty) {
    params["appName"] = options.userProperty;
  }

  return params;
};

/**
 * Expose `Strategy`.
 */
module.exports = Strategy;

const requiredParamsValidator = (prm) => {
  throw new Error(`Missing required param ${prm}`);
};

const validateParams = (
  privateKey = requiredParamsValidator("privateKey"),
  {
    netPassportId = requiredParamsValidator("netPassportId"),
    initUri = requiredParamsValidator("initUri"),
    redirectUri = requiredParamsValidator("redirectUri"),
    successRedirect = requiredParamsValidator("successRedirect"),
    failureRedirect = requiredParamsValidator("failureRedirect"),
  }
) => true;

module.exports = {
  validateParams,
};

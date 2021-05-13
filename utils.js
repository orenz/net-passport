const requiredParamsValidator = (prm) => {
  throw new Error(`Missing required param ${prm}`);
};

const validateParams = (
  privateKey = requiredParamsValidator("privateKey"),
  {
    domain = requiredParamsValidator("domain"),
    successRedirect = requiredParamsValidator("successRedirect"),
    failureRedirect = requiredParamsValidator("failureRedirect"),
  }
) => true;

module.exports = {
  validateParams,
};

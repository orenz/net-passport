# Net Passport

net-passport is a all-strategy (Google, Facebook, etc...) server side authentication using Passport JS mechanism in just a single line of code.
You don't need any more boilerplates, repetitive configurations, strategies installations and more.
Just use net-passport middleware in your express application and manage your authenticated users!
In addition, net-passport gives you a simple way for sign and verify messages using your NetPassport ID.

## Installation

```
$ npm install net-passport
```

## Usage

```javascript
const { NetPassport } = require("net-passport");

// Just register into netpassport.io and manage your authenticated users for free.

// Create an object with the relevant parameters
const params = {
  netPassportID: 112233,  // **required** your NetPassport id
  initURI: "/", // **required** your base auth path
  redirectUri: "/auth/callback", // **required** callback auth path so NetPassport could recieve authentication callback
  successRedirect: "/success", // **required** a success relative path in case user authenticated successfully
  failureRedirect: "/failed", // ***required** a failed relative path for failed authentication
}

// You can choose one private key option
const pk = {
  privateKey: fs.readFileSync(pathToPrivateKey, { encoding: "utf-8" }) // client privateKey file encoded in utf-8
}

// OR

const pk = {
  privateKeyPath: path.join(__dirname, ssl, "myPrivateKey.pem") // optional, instead of privateKey as file, send the path to your pk
}

// Use NetPassport in a top level middleware
app.use(NetPassport.authenticate(params, pk));

// Define success and failed routs
app.get("/success", (req, res) => {
  res.send(`Hello ${req.session.user.name}`);
});

app.get("/failed", (req, res) => {
  res.send(`Failed authentication`);
});


```

## License

[MIT](https://choosealicense.com/licenses/mit/)

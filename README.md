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
const { netPassport } = require("net-passport");

// Just register into netpassport.io and manage your authenticated users for free.

// Create an object with the relevant parameters
const message = {
  netPassportID: 112233, // **required** your NetPassport id
  initURI: "/", // **required** your base auth path
  redirectUri: "/auth/callback", // **required** callback auth path so NetPassport could recieve authentication callback
  successRedirect: "/success", // **required** a success relative path in case user authenticated successfully
  failureRedirect: "/failed", // ***required** a failed relative path for failed authentication
  appName: "myAwesomeApp", // Optional - application name 
};

```

### Add your private key

```javascript
// Pass in the .pem file or a pth to the file
const pk = fs.readFileSync(
  path.join(__dirname, "lib", "keys", "privatekey.pem"),
  "utf-8"
);

// OR

const pk = path.join(__dirname, "lib", "keys", "privatekey.pem")
```


### Define middlewares

```javascript
// Use NetPassport in a top level middleware
app.use(netPassport.authenticate(pk, message));

// Define success and failed routs
app.get("/success", (req, res) => {
  res.send(`Hello ${req.session.passport.user.full_name}`);
});

app.get("/failed", (req, res) => {
  res.send(`Failed authentication`);
});
```

## Server to server authentication

#### Sign data

```javascript
// Initiate your message object
const message = {
  netPassportID: 112233,
  myData: "Hi there"
};

// Pass in two parameters that includes private key or path to your private key and your object message (as mentioned above)
const signature = netPassport.sign(pk, message);
```

#### Verify data

```javascript
// Pass in two parameters that includes your original object message and the hashed signature of the message
netPassport.verify(message, signature);
```

## License

[MIT](https://choosealicense.com/licenses/mit/)

var express = require('express');
var bodyParser = require('body-parser');
var MD5 = require('md5');
var app = express();



var fs = require('fs')
    , ursa = require('ursa');////https://github.com/quartzjer/ursa


//Important: change $secretCode, $privateKey value (go to:  http://developer-vstack.vht.com.vn, choose your app, click menu: Keys)
var secretCode = "c21d5ecff0c1eece";
var rsa = ursa.createPrivateKey(fs.readFileSync('./private_key.pem'));



//config server
var serverPort = 8080;



app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: false }));

//authentication
app.use('/', function(req, res, next) {
  var result = 1;

  //get request token
  var token = req.body.token;
  console.log("\n\n\n============ New request ===========\nToken: " + token);
  if(token !== undefined && token.length > 0) {
    //get message
    var message = JSON.parse(rsa.decrypt(token, 'base64', 'utf8', ursa.RSA_PKCS1_PADDING));
    console.log("Message decrypted: ", message);

    //get app id
    var appId = message.appId;

    //get azStackUserID
    var azStackUserID = message.azStackUserID;

    //get timestamp
    var timestamp = message.timestamp;

    //get code
    var code = message.code;

    //get userCredentials
    var userCredentials = message.userCredentials;

    //verify code = md5(appId . "_" . timestamp . "_" . secretCode)
    //		to make sure request is from VStack
    if(code == MD5(appId + "_" + timestamp + "_" + secretCode) ){
      //check user credentials
      var userCredentialsValid = true;

      //you can validate $azVStackUserID and $userCredentials in your Database, etc
      //...
      if (userCredentialsValid) {
          result = 0;
      }
    }
  }

  res.send({
    result: result
  });
  console.log("Result: ", {
    result: result
  });
});


app.listen(serverPort, function() {
  console.log("Server running at port " + serverPort);
});

module.exports = app;


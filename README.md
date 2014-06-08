ssh-signer
==========

A ssh key sign and verify tool.

Install
==========
```bash
npm install ssh-signer
```

Use
==========
Prepare..., require modules and option parameter
```javascript
var signer = require('ssh-signer')
  , fs = require('fs');

var opt = {
  alg:'RSA-SHA256',
  hash:'base64'
}
```

Sign a SSH key (opt can be null for using default)
```javascript
//sign a key from public key path
var a = signer.signPrivateKey( 'Test123', '/root/.ssh/id_rsa', opt);

//sign a key from public key string
var privKeyStr = fs.readFileSync('/root/.ssh/id_rsa', 'UTF-8');
var a = signer.signPrivateKeyStr( 'Test123', privKeyStr, opt);
```

Verify a key (opt can be null for using default)
```javascript
//verify a key from public key path
var b = signer.verify(a, 'Test123', '/root/.ssh/id_rsa.pub', opt);

//verify a key from public key string
var pubKeyStr = fs.readFileSync('/root/.ssh/id_rsa.pub', 'UTF-8');
var b = signer.verifyStr(a, 'Test123', pubKeyStr, opt );
console.log('Verify result ==> ' + b); //will show true or false
```

Generate PEM RSA key pair
```javascript
var signer = require('ssh-signer');
// default is 1024 bit key
var key = signer.sshkeygen();
// use other configures
var keys = signer.sshkeygen({
  bits: 2048
});
```

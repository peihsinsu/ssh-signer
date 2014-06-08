var crypto=require("crypto")
  , sys=require("sys")
  , fs=require("fs")
  , hs = require('http-signature')
	, keypair = require('keypair')
  , ENCODE = 'UTF-8'
  , hash = 'base64'
  , alg = 'RSA-SHA256';

/**
 * sign the private key, the input privateKey is the path of private key
 * @param {String} seed The seed that use for disturb the key
 * @param {String} privateKey The path where the private key exist
 * @param {String} opt The option data that include hash(hash method) and alg(algorithm)
 * 
 * Example:
 * var signer = require('ssh-signer');
 * var seed = 'Test123';
 * var opt = {
 *   alg:'RSA-SHA256',
 *   hash:'base64'
 * }
 * var a = signer.signPrivateKey( seed , '/root/.ssh/id_rsa', opt);
 * console.log(a);
 */
function signPrivateKey(seed, privateKey, opt) {
  var privKey = fs.readFileSync(privateKey, ENCODE);
  return signPrivateKeyStr(seed, privKey, opt);
}
exports.signPrivateKey = signPrivateKey;

/**
 * sign the private key
 * @param {String} seed The seed that use for disturb the key
 * @param {String} privateKeyStr The private key string
 * @param {String} opt The option data that include hash(hash method) and alg(algorithm)
 * 
 * Example:
 * var signer = require('ssh-signer');
 * var seed = 'Test123';
 * var opt = {
 *   alg:'RSA-SHA256',
 *   hash:'base64'
 * }
 * var k = fs.readFileSync('/root/.ssh/id_rsa', 'UTF-8');
 * var a = signer.signPrivateKey( seed , k, opt);
 * console.log(a);
 */
function signPrivateKeyStr(seed, privateKeyStr, opt) {
  var signer;
  if(opt) {
    signer = crypto.createSign(opt.alg).update(seed);
    return signer.sign(privateKeyStr, opt.hash);
  } else {
    signer = crypto.createSign(alg).update(seed);
    return signer.sign(privateKeyStr, hash);
  }
}
exports.signPrivateKeyStr = signPrivateKeyStr;

/**
 * verify the key using public key, input publicKey is the path of public key
 * @param {String} secrit The signed ssh key string
 * @param {String} seed The seed that use for disturb the key
 * @param {String} publicKey The path where the public key exist
 * @param {String} opt The option data that include hash(hash method) and alg(algorithm)
 *
 * Example:
 * var signer = require('ssh-signer');
 * var seed = 'Test123';
 * var opt = {
 *   alg:'RSA-SHA256',
 *   hash:'base64'
 * }
 * var inputData = 'the signed public key text';
 * var b = signer.verify(inputData, seed, '/root/.ssh/id_rsa.pub', opt);
 * console.log('Verify result ==> ' + b);
 */
function verify(secrit, seed, publicKey, opt) {
  var pubKey = fs.readFileSync(publicKey, ENCODE);
  return verifyStr(secrit, seed, pubKey, opt); 
}
exports.verify = verify;

/**
 * verify the key using public key, input publicKeyStr is the key string of public key
 * @param {String} secrit The signed ssh key string
 * @param {String} seed The seed that use for disturb the key
 * @param {String} publicKeyStr The string of the public key
 * @param {String} opt The option data that include hash(hash method) and alg(algorithm)
 *
 * Example:
 * var signer = require('ssh-signer');
 * var seed = 'Test123';
 * var opt = {
 *   alg:'RSA-SHA256',
 *   hash:'base64'
 * }
 * var inputData = 'the signed public key text';
 * var pubKey = fs.readFileSync('/root/.ssh/id_rsa.pub', 'UTF-8');
 * var b = signer.verifyStr(inputData, seed, pubKey, opt);
 * console.log('Verify result ==> ' + b);
 */
function verifyStr(secrit, seed, publicKeyStr, opt) {
  var pem = null;
	if ( publicKeyStr.indexOf('-----BEGIN RSA PUBLIC KEY-----') == 0)
		pem = publicKeyStr;
	else if (publicKeyStr.indexOf('ssh-rsa ') == 0) 
		pem = hs.sshKeyToPEM(publicKeyStr);
	else {
		log.error('[ERROR] public key format exception');
		return null;
	}
  var ver;
  if(opt) {
    ver = crypto.createVerify(opt.alg);
    ver.update(seed);
    return ver.verify(pem, secrit, opt.hash);
  } else {
    ver = crypto.createVerify(alg);
    ver.update(seed);
    return ver.verify(pem, secrit, hash);
  }
}
exports.verifyStr = verifyStr;

/**
 * Generate PEM RSA key pair
 * @param {json} opt The other information for keypair generate
 */
exports.sshkeygen = function(opt) {
	if(opt)
		return keypair(opt);
	else
		return keypair();
}

#!/usr/local/bin/node

const crypto = require('crypto'), fs = require("fs");

function encode_aes192(data){
  var cipher = crypto.createCipher('aes192', server_key);
  cipher.update(data.toString(), 'utf8', 'hex');
  return cipher.final('hex');
}
function decode_aes192(hex){
  var decipher = crypto.createDecipher('aes192', server_key);
  decipher.update(hex.toString(), 'hex', 'utf8');
  return decipher.final('utf8');
}

var realm='ProxyJS.com - Proxy Authetication Required';
var server_key = fs.readFileSync('server-key.pem').toString();
var username=process.argv[2] || '';
var password=process.argv[3] || '';

if(username==''||password==''||password.length>15) return;

console.log(username+':'+encode_aes192(password));

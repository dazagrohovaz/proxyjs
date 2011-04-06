/**
// Copyright DazaGrohovaz.Net / ProxyJS.com
//
// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the
// "Software"), to deal in the Software without restriction, including
// without limitation the rights to use, copy, modify, merge, publish,
// distribute, sublicense, and/or sell copies of the Software, and to permit
// persons to whom the Software is furnished to do so, subject to the
// following conditions:
//
// The above copyright notice and this permission notice shall be included
// in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
// OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN
// NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
// DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
// OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE
// USE OR OTHER DEALINGS IN THE SOFTWARE.
**/

/*
HOW TO USE:
echo 'facebook.com' >> blacklist
echo '1.2.3.4' >> iplist
echo '80' >> portlist
echo '443' >> portlist
echo 'yourdomain.com 192.168.0.2' >> reverse_servers
echo 'www.yourdomain.com 192.168.0.3' >> reverse_servers
echo 'somethingelse.yourdomain.com mynetinternaldnsname' >> reverse_servers

TIPP:
reverse_server list work only with http-protocol. And without WebSocket support ( For Now ;) )
if you want use this with https too, you need to add some lines into the /etc/hosts file
echo '192.168.0.3 www.yourdomain.com' >> /etc/hosts
*/

const crypto = require('crypto'),
      fs = require("fs"),
      http = require("http"),
      net = require('net'),
      url = require('url');

var   realm = 'ProxyJS.com - Proxy Authetication Required', // don't use coma , or quotes " or equal =
      proxy_agent = 'proxyjs.v.0.1.0',  // don't use coma , or quotes " or equal =
      nonce_max_duration = 30, // minutes
      nonce_max_count = 150,
      server_key = fs.readFileSync('server-key.pem').toString();
      // i use as server key a file created with openssl
      // plaintext can be used here
      // that it used to encode and decode passwords
      // it is required to http/proxy authetication  

var   PORT = 8000,
      PORT_SSL = 443, // only require for HTTPS reverse proxy.  not implemented jet.
      run_as = 'forward' // 'forward' or 'reverse' 
      debug = true,
      use_auth_control = true, // set true to activate this
      use_blacklist_control = true, // set true to activate this
      use_iplist_control = true, // set true to activate this
      use_portlist_control = true, // set true to activate this
      use_http_reverse_service = true; // set true to activate this
      use_CONNECT_support = true; // set true to activate this
      // use_CONNECT_support is required for https and socks (transfer binary data) 

var   users = [],
      blacklist = [],
      iplist = [],
      portlist = [],
      reverse_servers = [];

var   blacklist_file = './blacklist',
      iplist_file = './iplist',
      portlist_file = './portlist',
      reverse_servers_file = './reverse_servers',
      users_file = './users';

var   filteredHeaders = ['proxy-connection', 'set-cookie', 'accept-encoding', 'connection', 'keep-alive', 'proxy-authenticate', 'upgrade', 'proxy-authorization', 'trailers', 'transfer-encoding'];

if (use_auth_control) fs.watchFile(users_file, function(c,p) { update_user_list(); });
if (use_blacklist_control) fs.watchFile(blacklist_file, function(c,p) { update_blacklist(); });
if (use_iplist_control) fs.watchFile(iplist_file, function(c,p) { update_iplist(); });
if (use_portlist_control) fs.watchFile(portlist_file, function(c,p) { update_portlist(); });
if (use_http_reverse_service) fs.watchFile(reverse_servers_file, function(c,p) { update_reverse_service(); });

function update_user_list() {
  log("Updating user list.");
  users = fs.readFileSync(users_file).toString().split('\n')
              .filter(function(rx) { return rx.length });
}
function update_blacklist() {
  log("Updating blacklist.");
  blacklist = fs.readFileSync(blacklist_file).toString().split('\n')
              .filter(function(rx) { return rx.length })
              .map(function(rx) { return RegExp(rx) });
}
function update_iplist() {
  log("Updating iplist.");
  iplist = fs.readFileSync(iplist_file).toString().split('\n')
           .filter(function(rx) { return rx.length });
}
function update_portlist() {
  log("Updating portlist.");
  portlist = fs.readFileSync(portlist_file).toString().split('\n')
           .filter(function(rx) { return rx.length });
}
function update_reverse_service() {
  log("Updating reverse servers.");
  reverse_servers = fs.readFileSync(reverse_servers_file).toString().split('\n')
              .filter(function(rx) { return rx.length });
}
function log(msg){
  if (debug) console.log(msg);
}
function host_allowed(host) {
  for (i in blacklist) {
    if (blacklist[i].test(host)) {
      return false;
    }
  }
  return true;
}
function ip_allowed(ip) {
  for (i in iplist) {
    if (iplist[i] == ip) {
      return true;
    }
  }
  return false;
}
function port_allowed(port) {
  for (i in portlist) {
    if (portlist[i] == port) {
      return true;
    }
  }
  return false;
}
function get_user_password(username) {
  for (i in users) {
    user = users[i].split(':');
    if (user[0] == username) {
      return user[1];
    }
  }
  return null;
}
function reverse_server(host) {
  for (i in reverse_servers) {
    try {
      var route = reverse_servers[i].split(' ');
      route[0] = route[0].trim();
      route[1] = route[1].trim();
      if (route[0]==host) {
        return route[1];
      }
    } catch (e) {
      // return host;
    }
  }
  return host;
}
function auth_allowed(req, socket){
  if(!req.headers['proxy-authorization']){
    auth_required(req, socket);
    return false;
  } else {
    var header = req.headers['proxy-authorization'];
    var digest = header.slice(0,6);
    if (digest!="Digest"){
      auth_required(req, socket);
      return false;
    }
    var auth = {};
    var params = header.slice(7).split(', ');
    for(var i in params){
      var item = params[i].toString().trim().replace("=","°^°").split("°^°");
      item[1] = item[1].toString().replace('"','').replace('"','');
      auth[item[0].toLowerCase()] = item[1];
      params[i] = item;
    };
    if((!auth.username&&auth.username!='')||!auth.realm||!auth.nonce||!auth.uri||!auth.response||!auth.opaque||!auth.qop||!auth.nc||!auth.cnonce){
      deny_request(req, socket);
      return false;
    }
    auth.username = auth.username.toLowerCase();
    auth.password = get_user_password(auth.username);
    if(!auth.password){
      log('username or password are invalid. Remote Address: '+req.connection.remoteAddress+' - '+req.url)
      auth_required(req, socket);
      return false;
    }
    auth.method = req.method;
    var HA1 = hex_md5(''.concat(auth.username,':',auth.realm,':',decode_aes192(auth.password)));
    var HA2 = hex_md5(''.concat(auth.method,':',auth.uri,''));
    var response = hex_md5(HA1+':'+auth.nonce+':'+auth.nc+':'+auth.cnonce+':'+auth.qop+':'+HA2);
    if(response != auth.response){
      log('request-digest is invalid. Remote Address: '+req.connection.remoteAddress+' - '+req.url)
      deny_request(req, socket);
      return false;
    }
    var timestamp = (new Date).getTime();
    var expires = parseInt(decode_aes192(auth.opaque));
    if(!expires||(expires+(24*60*1000)) < timestamp){ // request username and password if expires is one day old for security reasons
      auth_required(req, socket);
      return false;
    }
    var nc = parseInt(auth.nc, 16);
    var nonce = hex_md5(expires+":"+req.connection.remoteAddress+":"+server_key);
    if((nonce_max_count && nonce_max_count < nc)||(nonce != auth.nonce)||(expires < timestamp && nonce == auth.nonce)){
      auth_required(req, socket,'true');
      return false;
    }
    return true;
  }
}
function auth_required(req, socket, stale){
  if(!stale)stale='false';
  var timestamp = (new Date).getTime();
  var expires = timestamp+(nonce_max_duration*60*1000);
  var nonce = hex_md5(expires+":"+req.connection.remoteAddress+":"+server_key);
  var opaque = encode_aes192(expires);
  socket.write( 'HTTP/1.0 407 Proxy Authentication Required\r\n'
              + 'Proxy-agent: '+proxy_agent+'\r\n'
              + 'Proxy-Authenticate: Digest '
              +                     'realm="'+realm+'",'
              +                     'qop="auth",'
              +                     'stale="'+stale+'",'
              +                     'nonce="'+nonce+'",'
              +                     'opaque="'+opaque+'"'
              +                     '\r\n'
              + '\r\n');
  socket.end();
}
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
function hex_md5(data){
  return crypto.createHash('md5').update(data).digest('hex');
}
function cleanHeaders(h) {
  cleaned = {};
  for(var p in h) {
    if (filteredHeaders.indexOf(p) == -1) {
      cleaned[p] = h[p];
    }
  }
  return cleaned;
}
function responseContentType(headers) {
  try {
    if (headers['content-encoding'] == "gzip" || 
        (headers['content-type'].indexOf("text/") == -1)) {
      return "binary";
    } else {
      return "utf8"
    }
  } catch(e) {
    return "utf8";
  }
}
function request_allowed(req, socket){
  var allowed_auth = !use_auth_control;
  var allowed_host = !use_blacklist_control;
  var allowed_ip = !use_iplist_control;
  var allowed_port = !use_portlist_control;
  
  var strUrl = ''+req.url;
  strUrl = (strUrl.slice(0,1)=='/')?strUrl.slice(1):strUrl;
  var Url = url.parse(strUrl);
  
  var options = {
    host: Url.hostname || Url.host || req.headers.host || '',
    port: Url.port || ((req.method=='CONNECT')?443:((/GET|HEAD|POST|PUT|DELETE/).test(req.method))?80:''),
    path: (Url.pathname || '/') + (Url.search || ''),
    method: req.method
  };
  
  if(use_auth_control){
    allowed_auth = auth_allowed(req, socket);
    if(!allowed_auth)return false;
  }
  if(use_blacklist_control){
    allowed_host = host_allowed(options.host);
    if (!allowed_host){
      msg = "Host " + req.url + " has been denied by proxy configuration";
      deny_request(req, socket, {errno:1,message:msg});
      return false;
    }
  }
  if(use_iplist_control){
    var ip = req.connection.remoteAddress;
    allowed_ip = ip_allowed(ip);
    if (!allowed_ip) { 
      msg = "IP " + ip + " is not allowed to use this proxy";
      deny_request(req, socket, {errno:1,message:msg});
      return false;
    }
  }
  if(use_portlist_control){
    if(options.port!=''){
      allowed_port = port_allowed(options.port);
    }
    if(!allowed_port){
      msg = "PORT " + options.port + " is not allow on this proxy";
      deny_request(req, socket, {errno:1,message:msg});
      return false;
    }
  }
  return allowed_auth && allowed_host && allowed_ip && allowed_port
}
function connection_established(req, socket){
  socket.write( 'HTTP/1.1 200 Connection established\r\n'
              + 'Proxy-agent: '+proxy_agent+'\r\n'
              + '\r\n'
              );
}
function deny_request(req, socket, e){
  if(!e)e={errno:0,message:'Bad Request'};
  socket.write( 'HTTP/1.0 '+(400+e.errno)+' '+e.message+'\r\n'
              + 'Proxy-agent: '+proxy_agent+'\r\n'
              + '\r\n'
              + (400+e.errno)+' '+e.message+'\r\n');
  socket.end();
  log(e.message);
}
function http_handler(req, res){
  if (!request_allowed(req, res.socket)) return;
  
  var encoding = responseContentType(req.headers);
  
  var strUrl = ''+req.url;
  strUrl = (strUrl.slice(0,1)=='/')?strUrl.slice(1):strUrl;
  var Url = url.parse(strUrl);
  
  var options = {
    host: Url.hostname || Url.host || req.headers.host || '',
    port: Url.port || 80,
    path: (Url.pathname || '/') + (Url.search || ''),
    method: req.method
  };
  
  if(run_as == 'reverse'){ // 'forward' or 'reverse'
    if(options.path.slice(0,1)!='/' && Url.protocol != 'http:')options.path = '/'+options.path;
    if(!Url.protocol)Url.protocol = 'http:';
  }
  
  if(options.host == '' || Url.protocol != 'http:'){
    deny_request(req, res.socket)
    return;
  };
  
  if (use_http_reverse_service) {
    var reverse_host = reverse_server(options.host); 
    if( options.host != reverse_host){
      log('Redirecting ' +  Url.protocol + '//' + options.host + options.path + ' to ' + Url.protocol + '//' + reverse_host + options.path);
      options.host = reverse_host;
    }
  }
  var proxy = http; 
  
  // create request object and response callback
  var proxyReq = proxy.request(options, function(proxyRes){
     log('Connection established: '+req.method+' '+req.url)
     var encoding = responseContentType(proxyRes.headers);
    
    // return status code and headers to the client
    res.statusCode = proxyRes.statusCode;
    for(var header in proxyRes.headers){
      res.setHeader(header, proxyRes.headers[header]);
    };
    
    // return data chunk to the cliente
    proxyRes.on('data', function (chunk) {
       res.write(chunk, encoding);
    });

    // close client connection
    proxyRes.on('end',function(){
      res.end('');
    });
  });
  
  // send headers to the server
  var headers = cleanHeaders(req.headers)
  for(var header in headers){
    proxyReq.setHeader(header, headers[header]);
  };
  
  // send data chunk to the server
  req.on('data', function(chunk){
    try {
      proxyReq.write(chunk, encoding);
    }catch(e){}
  });
  
  // close request object
  req.on('end', function(){
    try {
      proxyReq.end();
    }catch(e){}
  });
  proxyReq.on('error',function(e){
    try {
    deny_request(req, res.socket, e);
    }catch(e){
      try {
        proxyReq.end();
        res.end('');
      }catch(e){}
    }
  });
};
function upgrade_handler(req, socket, upgradeHead) {
  if (!request_allowed(req, socket)) return;
  
  if (!(/CONNECT|GET/).test(req.method)) { // CONNECT binary (HTTPS/WebSocket as Forward-Proxy) , GET WebSocket (as Reverse-Proxy) 
    msg = "Request " + req.method + " is not supported on this proxy";
    deny_request(req, socket, {errno:0,message:msg});
    log(msg);
    return;
  }
  if(run_as = 'forward'){ // 'forward' or 'reverse'
    if ((/GET/).test(req.method)) { // this is required for reverse-proxy implementation
      msg = "Request " + req.method + " is not supported on this proxy";
      deny_request(req, socket, {errno:0,message:msg});
      log(msg);
      return;
    }
  }
  if(run_as = 'reverse'){ // 'forward' or 'reverse'
    if ((/GET/).test(req.method)) { // this is required for reverse-proxy implementation
      //websocket_handler(req, socket); // not implemented
      // this "deny_request" call should deleted after the WebSocket implementation
      msg = "Request " + req.method + " is not supported on this proxy";
      deny_request(req, socket, {errno:0,message:msg});
      log(msg);
      // this "deny_request" call should deleted after the WebSocket implementation
      return;
    }
  }
  var strUrl = ''+req.url;
  strUrl = (strUrl.slice(0,1)=='/')?strUrl.slice(1):strUrl;
  if(strUrl.slice(0,8)!='https://') strUrl = 'https://'+strUrl;
  var Url = url.parse(strUrl);
  var options = {
    host: Url.hostname || Url.host || '',
    port: Url.port || 443
  };
  
  if(options.host == ''){
    deny_request(req, socket)
    return;
  };
  
  var proxySocket = new net.Socket();

  proxySocket.connect(options.port, options.host, function() {
    log('Connection established: '+req.method+' '+req.url)
    connection_established(req, socket);
    proxySocket.on('data', function (data) {
      try { socket.write(data); } catch(e){
        try { proxySocket.end(); } catch(e){}
        try { socket.end(); } catch(e){}
      }
    });
    proxySocket.on('end', function () {
      socket.end();
    });
  });
  proxySocket.on('error', function () {
    try { proxySocket.end(); } catch(e){}
    try { socket.end(); } catch(e){}
  });
  proxySocket.on('timeout', function () {
    try { proxySocket.end(); } catch(e){}
    try { socket.end(); } catch(e){}
  });
  socket.on('data', function(data){
    try { proxySocket.write(data); } catch(e){
      try { proxySocket.end(); } catch(e){}
      try { socket.end(); } catch(e){}
    }
  });
  socket.on('end', function(){
    proxySocket.end();
  });
  socket.on('error', function () {
    try { proxySocket.end(); } catch(e){}
    try { socket.end(); } catch(e){}
  });
  socket.on('timeout', function () {
    try { proxySocket.end(); } catch(e){}
    try { socket.end(); } catch(e){}
  });
};
function error_handler(e){
  log("Got error: " + e.message);
  // Attach your code here
}

var server = http.createServer()

server.addListener('error', error_handler);
server.addListener("request", http_handler);
if ( use_CONNECT_support ) server.addListener("upgrade", upgrade_handler);

server.listen(PORT /*,'localhost'*/); // localhost should be the ip_address to listen (like 10.0.0.1) 

if (use_auth_control) update_user_list();
if (use_blacklist_control) update_blacklist();
if (use_iplist_control) update_iplist();
if (use_portlist_control) update_portlist();
if (use_http_reverse_service) update_reverse_service();

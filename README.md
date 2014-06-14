# Bud [![Build Status](https://secure.travis-ci.org/indutny/bud.png)](http://travis-ci.org/indutny/bud)

A TLS terminator for superheroes.

## What is bud?

Bud is a TLS terminating proxy, a babel fish decoding incoming TLS traffic and
sending it in a plain text to your backend servers. Not only it does it, but
does it good and with a lot of useful features!

## Install

Bud can easily be installed using [npm](http://npmjs.org)

``` bash
[sudo] npm install bud-tls
```

This will install the command line tool `bud`.  Optionally, you can build
Bud from source with the steps below.

## Build

Preparing:
```bash
git submodule update --init --recursive
svn co http://gyp.googlecode.com/svn/trunk tools/gyp
```

Building:
```bash
./gyp_bud
make -C out/
```

The result will be located at: `./out/Release/bud`.

## Starting

To start bud - create configuration file using this template and:

```bash
bud --conf conf.json
```

## Configuration

Bud is using [JSON][0] as a configuration format. Run `bud --default-config`
to get default configuration options (with comments and description below):

```javascript
{
  // Number of workers to use, if 0 - only one process will be spawned.
  "workers": 1,

  // Timeout after which workers will be restarted (if they die)
  "restart_timeout": 250,

  // Logging configuration
  "log": {
    // Minimum observable log level, possible values:
    // "debug", "notice", "info" (default), "warning", "fatal"
    "level": "info",

    // syslog facility to use, could be:
    // "auth", "cron", "kern", "lpr", "mail", "news", "syslog"
    // "deamon", "uucp", "local0", ... "local7"
    "facility": "user",

    // if true - logging will be printed to standard output
    "stdio": true,

    // if true - syslog will be used for logging
    "syslog": true
  },

  // Availability configuration
  "availability": {
    // Maximum number of backend reconnects before giving up
    "max_retries": 5,

    // Time between retries
    "retry_interval": 250,

    // How long backend should not be responding until considered to bedead
    "death_timeout": 1000,

    // Timeout after which it should be revived
    "revive_interval": 2500
  },

  // Frontend configuration (i.e. TLS/SSL server)
  "frontend": {
    "port": 1443,
    "host": "0.0.0.0",

    // tcp keepalive value (in seconds)
    "keepalive": 3600,

    // if true - server listed ciphers will be preferenced
    "server_preference": true,

    // Which protocol versions to support:
    // **optional**, default: "ssl23"
    // "ssl23" (implies tls1.*) , "ssl3", "tls1", "tls1.1", "tls1.2"
    "security": "ssl23",

    // Path to default TLS certificate
    "cert": "keys/cert.pem",

    // Path to default TLS private key
    "key": "keys/key.pem",

    // **Optional** Passphrase for the private key
    "passphrase": null,

    // **Optional** Cipher suites to use
    "ciphers": null,

    // **Optional** ECDH Curve to use
    "ecdh": "prime256v1",

    // **Optional** Base64 encoded TLS session ticket key,
    // should decode into 48 raw bytes
    "ticket_key": "yzNUDktR5KmA4wX9g9kDSzEn+3+7HjCXrI+kz4tTxNL22tnPyd+2gqEW608LRBh8",

    // **Optional** NPN protocols to advertise
    "npn": ["http/1.1", "http/1.0"],

    // NOTE: Better leave this default:

    // **Optional** Renegotiation window in seconds
    "reneg_window": 300,

    // **Optional** Maximum number of renegotiations in a window
    "reneg_limit": 3,

    // **Optional** If true - enable SSL3 support
    "ssl3": false,

    // **Optional** Maximum size of TLS fragment
    "max_send_fragment": 1400,

    // **Optional** If false - close frontend connection on backend EOF
    "allow_half_open": false,

    // **Optional** If true - the clients will be requested to provide the cert
    "request_cert": true,

    // **Optional**: Either filename or array of PEM certificate chain that
    // should be used for validating client certs
    "ca": "filename"
    // "ca": [ "-----BEGIN CERTIFICATE----\n..." ]
  },

  // Balance tactic
  // **Optional** possible values: "roundrobin", "sni"
  "balance": "roundrobin"

  // Backend configuration (i.e. address of Cleartext server)
  "backend": [{
    "port": 8000,
    "host": "127.0.0.1",
    "keepalive": 3600,

    // if true - HAProxy compatible proxyline will be sent:
    // "PROXY TCP4 ... ... ... ..."
    // if "json":
    // 'BUD {"family":"TCP4","bud":{"host":"...","port":...},"peer":{...}'
    "proxyline": false,

    // if true:
    // - if NPN is enabled and either `spdy/3.1`, `spdy/3` or `spdy/2` is
    //   negotiated - custom `X_FORWARDED` frame will be sent on connection.
    //   see: https://groups.google.com/forum/#!topic/spdy-dev/XkdtuShtVCEadds
    //
    // - in all other cases `X-Forwarded-For: <address>` will be added right
    //   after the first line in the incoming data.
    //
    // - in order to avoid parsing each request, the `X-Forwarded-For` header
    //   will only be sent on the first client request.

    "x-forward": false
  }],

  // SNI context loading
  "sni": {
    "enabled": false,
    "port": 9000,
    "host": "127.0.0.1",

    // %s will be replaced with actual servername
    "query": "/bud/sni/%s"
  },

  // OCSP Stapling response loading
  "stapling": {
    "enabled": false,
    "port": 9000,
    "host": "127.0.0.1",

    // %s will be replaced with actual servername
    "query": "/bud/stapling/%s"
  },

  // Secure contexts (i.e. Server Name Indication support)
  "contexts": [{
    // Servername to match against
    "servername": "blog.indutny.com",

    // Path to TLS certificate
    "cert": "keys/cert.pem",

    // Path to TLS private key
    "key": "keys/key.pem",

    // **Optional** Passphrase for the private key
    "passphrase": null,

    // Cipherlist to use (overrides frontend.ciphers, if not null)
    "ciphers": null,

    // ECDH curve to use, overrides frontend.ecdh
    "ecdh": null,

    // TLS session ticket key to use, overrides frontend.ticket_key
    "ticket_key": null,

    // NPN protocols to advertise
    // **optional** (overrides frontend.npn, if not null)
    "npn": ["http/1.1", "http/1.0"],

    // Backends to use, works only when "balance" is set to "sni"
    "backend": [{
      "port": 8000,
      "host": "127.0.0.1",
      "keepalive": 3600
    }],

    // **Optional** If true - the clients will be requested to provide the cert
    "request_cert": true,

    // **Optional**: Either filename or array of PEM certificate chain that
    // should be used for validating client certs
    "ca": "filename"
    // "ca": [ "-----BEGIN CERTIFICATE----\n..." ]
  }]
}
```

To start bud - create configuration file using this template and:

```bash
bud --conf conf.json
```

To reload config - send `SIGHUP` to the bud's master process (or worker, if you
wish to reload configuration only in a single process):

```bash
kill -SIGHUP <bud-master's-pid>
```

### X-Forwarded-For

Setting `backend.*.x-forward` will cause an `X-Forwarded-For` header to be injected
into the first request seen on a socket.  However, subsequent request using the
same socket (via Keep-Alive), will not receieve this header from `bud`.  To remedy this,
you should associate this header with the underlying socket or connection, and not expect
it to be present with every HTTP request.  A possible implementation in Node.JS would look
like:

``` js
var http = require('http');
http.createServer(onrequest).listen(8080, 'localhost');
function onrequest(req, res) {
  if (req.connection.xForward)
    req.headers['x-forwarded-for'] = req.connection.xForward;
  else if (req.headers['x-forwarded-for'])
    req.connection.xForward = req.headers['x-forwarded-for'];

  // handle request normally now, knowing that the `X-Forwarded-For` header is present now
}
```

### SNI Storage

If you have enabled SNI lookup (`sni.enabled` set to `true`), on every TLS
connection a request to the HTTP server will be made (using `sni.host`,
`sni.port` and `sni.query` as url template). The response should be a [JSON][0]
of the following form:

```javascript
{
  "cert": "certificate contents",
  "key": "key contents",

  // Optional
  "npn": [],

  // Optional
  "ciphers": "...",

  // Optional
  "ecdh": "..."
}
```

Or any other [JSON][0] and a 404 status code, if SNI certificate is not found.

If optional fields are not present - their value would be taken from `frontend`
object in configuration file.

### OCSP Stapling

OCSP Stapling has exactly the same configuration options as SNI Storage.
Main difference is that 2 requests to OCSP Stapling server could be made by bud:

1. `GET /stapling_url/<stapling_id>` - to probe backend's cache
2. `POST /stapling_url/<stapling_id>` with [JSON][0] body:
   `{"url":"http://some.ocsp.server.com/","ocsp":"base64-encoded-data"}`.

For first request, if backend has cached OCSP response for given
`<stapling_id>`, backend should respond with following [JSON][0]:

`{"response":"base64-encoded-response"}`

Or with 404 status code and any other [JSON][0].

For the second request, backend should send a POST request to the OCSP server
given in the [JSON][0] body. This request should have Content-Type header set
to `application/ocsp-request` and a decoded (from base64) `ocsp` field from
body.

The response to bud should be the same as in the first case, base64-encoded
data received from OCSP server.

#### Backend Example

Example OCSP+SNI backend implementation in node.js could be found [here][1].

#### Community

Join #bud-tls on freenode IRC to discuss things with me or others!

#### LICENSE

This software is licensed under the MIT License.

Copyright Fedor Indutny, 2013.

Permission is hereby granted, free of charge, to any person obtaining a
copy of this software and associated documentation files (the
"Software"), to deal in the Software without restriction, including
without limitation the rights to use, copy, modify, merge, publish,
distribute, sublicense, and/or sell copies of the Software, and to permit
persons to whom the Software is furnished to do so, subject to the
following conditions:

The above copyright notice and this permission notice shall be included
in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN
NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE
USE OR OTHER DEALINGS IN THE SOFTWARE.

[0]: http://json.org/
[1]: http://github.com/indutny/bud-backend

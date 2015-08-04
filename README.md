# Bud
[![Build Status](https://secure.travis-ci.org/indutny/bud.png)](http://travis-ci.org/indutny/bud)
[![NPM version](https://badge.fury.io/js/bud-tls.svg)](http://badge.fury.io/js/bud-tls)

A TLS terminator for superheroes.

## What is bud?

Bud is a TLS terminating proxy, a babel fish decoding incoming TLS traffic and
sending it in a plain text to your backend servers.
Not only does it do this well, bud has a lot of useful features!

## Why bud?

* Asynchronous key/cert loading using the supplied servername extension (SNI)
* Asynchronous selection of backend to balance (using SNI)
* Asynchronous OCSP stapling
* TLS ticket rotation across cluster of workers, or multi-machine cluster
  (needs separate utility to synchronize them, but the protocol is in-place)
* Availability: marking backends as dead, reviving them after period of time
* Multi-frontend mode of operation. Single bud instance might be bound to
  multiple different ports and interfaces
* Proxyline support: both HAProxy format at custom BUD JSON format
* X-Forwarded-For for first HTTP request, and custom frame for SPDY
  (soon HTTP2 too) connection
* Multi-context mode of operation, each context is used for different server
  name. All TLS parameters may be redefined in the context
* Support for simultaneous ECDSA and RSA certs and keys

## Implementation details

Bud is implemented fully in C, with the exception to the tests which are running
on [io.js][2]. The networking level is provided by [libuv][3], and the SSL
implementation by [OpenSSL][4] 1.0.2a.

## Install

### Requirements
You must have gcc installed. Chances are that you do, but in case you don't:

```bash
# OSX
# Command Line Tools for Xcode: xcode-select --install,
# https://developer.apple.com/downloads, or Xcode

# SmartOS
[sudo] pkgin update
[sudo] pkgin install gcc47

# Ubuntu
[sudo] apt-get update
[sudo] apt-get install build-essential
```

### Easy Install
Bud can easily be installed using [npm](http://npmjs.org)

``` bash
[sudo] npm install -g bud-tls
```

This will install the command line tool `bud`.  Optionally, you can build
Bud from source with the steps below.

### Build

Preparing:
```bash
git submodule update --init --recursive
Then:
git clone https://chromium.googlesource.com/external/gyp.git tools/gyp
OR
svn co http://gyp.googlecode.com/svn/trunk tools/gyp tools/gyp
```

Building:
```bash
./gyp_bud
make -C out/
```

The result will be located at: `./out/Release/bud`.

## Starting

To start bud - create a configuration file using this template and then:

```bash
bud --conf conf.json
```

### Options
```
Usage: bud [options]

options:
  --version, -v              Print bud version
  --config PATH, -c PATH     Load JSON configuration
  --piped-config, -p         Load piped JSON configuration
  --default-config           Print default JSON config
  --daemon, -d               Daemonize process
```


## Configuration

Bud uses [JSON][0] as the configuration format. Run `bud --default-config`
to get the default configuration options (with comments and description below):

```javascript
{
  // Number of workers to use, if 0 - only one process will be spawned.
  "workers": 1,

  // Timeout in ms after which workers will be restarted (if they die)
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

  // Availability of the backend
  "availability": {
    // Maximum number of backend reconnects before giving up
    "max_retries": 5,

    // Time between retries
    "retry_interval": 250,

    // How long backend should not be responding until considered to be dead -- ms
    "death_timeout": 1000,

    // Timeout in ms after which it should be revived
    "revive_interval": 2500
  },

  // Frontend configuration (i.e. TLS/SSL server)
  "frontend": {
    "port": 1443,
    "host": "0.0.0.0",

    // Alternatively you may want to specify multiple address to bind server to
    // "interfaces": [
    //   { "port": 1443, "host": "1.1.1.1" },
    //   { "port": 1444, "host": "2.2.2.2" }
    // ],

    // tcp keepalive value (in seconds)
    "keepalive": 3600,

    // if true - server listed ciphers will be preferenced
    "server_preference": true,

    // Which protocol versions to support:
    // **optional**, default: "ssl23"
    // "ssl23" (implies tls1.*): "tls1", "tls1.1", "tls1.2"
    "security": "ssl23",

    // Path to default TLS certificate
    // NOTE: Could be an array of cert strings
    // e.g. ["-----BEGIN CERTIFICATE-----...", "-----BEGIN CERTIFICATE-----..."]
    "cert": "keys/cert.pem",

    // Path to default TLS private key
    // NOTE: Could be an array of keys as file paths or strings
    "key": "keys/key.pem",

    // **Optional** Passphrase for the private key
    // NOTE: Could be an array of passphrases
    "passphrase": null,

    // **Optional** Cipher suites to use
    // Bud defaults to:
    // "ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA256:ECDHE-RSA-AES256-SHA256:DHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES256-GCM-SHA256:DHE-RSA-AES256-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-SHA256:ECDHE-RSA-AES128-SHA:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA:AES256-GCM-SHA384:AES256-SHA256:AES128-GCM-SHA256:AES128-SHA256:AES128-SHA:DES-CBC3-SHA"
    "ciphers": null,

    // **Optional** ECDH Curve to use, defaults to `prime256v1
    "ecdh": "prime256v1",

    // **Optional** Path to DH parameters file
    // **Recommend** generate a file
    // openssl dhparam -out dh.key 3072
    "dh": null,

    // **Optional** Base64 encoded TLS session ticket key,
    // should decode into 48 raw bytes
    // **Recommend** Generate with:
    // node -pe "require('crypto').randomBytes(48).toString('base64')"
    //
    // **Important note**: it should not be generally set, OpenSSL will generate
    // a random value for it at start, and ticket rotation will change it after
    // some time anyway
    "ticket_key": "yzNUDktR5KmA4wX9g9kDSzEn...true randomness",

    // **Optional** Ticket timeout in seconds, default: 3600
    "ticket_timeout": 3600,

    // **Optional** Interval between rotating ticket keys.
    // NOTE: If you are deploying bud to many boxes - please contact me, I'll
    // explain how ticket may be rotated simulatenously on all of them
    "ticket_rotate": 3600,

    // **Optional** NPN protocols to advertise
    "npn": ["http/1.1", "http/1.0"],

    // NOTE: Better leave this default:

    // **Optional** Renegotiation window in seconds
    "reneg_window": 300,

    // **Optional** Maximum number of renegotiations in a window
    "reneg_limit": 3,

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
  // **Optional** possible values: "roundrobin", "sni", or "on-fail"
  //
  // * "roundrobin" - on each new connection select next live backend
  // * "sni" - select backend list from either async sni or supplied contexts
  // * "on-fail" - select next backend in list only if the previous one is
  //   dead
  "balance": "roundrobin"

  // Unix-specific option, drop privileges after starting the process
  // **Recommend** Create a user and a group for bud.
  "user": null,
  "group": null,

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

    "x-forward": false,

    // *Optional key*
    // If this property is present - balancing will start from the backend,
    // which `external` value is matching server address.
    // (Useful when listening on multiple interfaces)
    "external": "[1.2.3.4]:443"
  }],

  // SNI context loading
  "sni": {
    "enabled": false,
    "port": 9000,
    "host": "127.0.0.1",

    // %s will be replaced with actual servername
    "url": "/bud/sni/%s"
  },

  // OCSP Stapling response loading
  "stapling": {
    "enabled": false,
    "port": 9000,
    "host": "127.0.0.1",

    // %s will be replaced with actual servername
    "url": "/bud/stapling/%s"
  },

  // Secure contexts (i.e. Server Name Indication support)
  "contexts": [{
    // Servername to match against
    "servername": "blog.indutny.com",

    // **Optional** balance algorithm, could not be `sni`
    "balance": "roundrobin",

    // Path to TLS certificate
    // Could be an array
    "cert": "keys/cert.pem",

    // Path to TLS private key
    // Could be an array
    "key": "keys/key.pem",

    // **Optional** Passphrase for the private key
    // Could be an array
    "passphrase": null,

    // Cipherlist to use (overrides frontend.ciphers, if not null)
    "ciphers": null,

    // ECDH curve to use, overrides frontend.ecdh
    "ecdh": null,

    // **Optional** Path to DH parameters file, overrides frontend.dh
    "dh": null,

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

To start bud - create a configuration file using this template:

```bash
bud --conf conf.json
```

To reload config - send `SIGHUP` to the bud's master process (or worker, if you
wish to reload configuration only in a single process):

```bash
kill -SIGHUP <bud-master's-pid>
```

### X-Forwarded-For

Setting `backend.*.x-forward` will cause an `X-Forwarded-For` header to be
injected into the first request seen on a socket. However, subsequent requests
using the same socket (via Keep-Alive), will not receive this header from `bud`.
To remedy this, you should associate this header with the underlying socket
or connection, and not expect it to be present with every HTTP request. A
possible implementation in Node.JS would look like:

``` js
var http = require('http')
http.createServer(onrequest).listen(8080, 'localhost')

function onrequest(req, res) {
  // this is a previous SSL request
  if (req.connection.xForward)
    req.headers['x-forwarded-for'] = req.connection.xForward;
  // this is a new SSL request
  else if (req.headers['x-forwarded-for'])
    req.connection.xForward = req.headers['x-forwarded-for'];
  // this is not an SSL request
  else {
    // optional, but a way to force SSL
    res.writeHead(301, {
      'Location': 'https://localhost:1443'
    })
    return void res.end()
  }


  // optional, it's a good idea to send this header to
  // force SSL in modern browsers
  res.setHeader('Strict-Transport-Security', 'max-age=' + 60 * 60 * 24 * 365)

  // handle request normally now knowing that the
  // `X-Forwarded-For` header is present
}
```

If you use nginx, the best results are achieved with the X-Real-IP module and
the `proxy_protocol` option. Add `proxy_protocol` to your nginx `listen`
directive. You may have to add a separate server block for traffic coming from
bud: the server with the `proxy_protocol` directive will not work with plain
HTTP requests.

```
server {
  # Accept and parse proxyline requests
  listen 127.0.0.1:8080 default proxy_protocol;

  # Use bud's proxyline info for the request IP
  real_ip_header proxy_protocol;

  # You may want to restrict which origin IPs can use the proxyline format
  set_real_ip_from 127.0.0.1;

  # [..]
}
```

The bud backend must be configured to use proxyline, too:

```
  "backend": [{
    "port": 8080,
    "host": "127.0.0.1",
    "keepalive": 3600,

    // this is where the magic happens
    "proxyline": true,

    // and now you can turn that off
    "x-forward": false,
  }],
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

  // **Optional** Path to DH parameters file, overrides frontend.dh
  "dh": null
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

For the first request, if backend has cached OCSP response for given
`<stapling_id>`, backend should respond with following [JSON][0]:

`{"response":"base64-encoded-response"}`

Or with a 404 status code and any other [JSON][0].

For the second request, backend should send a POST request to the OCSP server
given in the [JSON][0] body. This request should have Content-Type header set
to `application/ocsp-request` and a decoded (from base64) `ocsp` field from
body.

The response to bud should be the same as in the first case, base64-encoded
data received from OCSP server.

### Backend Example

Example OCSP+SNI backend implementation in node.js could be found [here][1].

### Generating a key and getting an ssl cert

Generating a key is easy with openssl

```bash
openssl genrsa -out server.key 2048
```

To generate the public certs, you'll need to buy an SSL cert from the provider
of your choice. They'll ask you to upload your key file, and the `.crt` file
generated below:

```bash
# you'll be asked for a bunch of info. The most important one is "common name"
# and this must match your domain exactly. e.g.
# example.com
# if you've bought a wildcard cert, you should use
# *.example.com
openssl req -new -key server.key -out server.csr
openssl x509 -req -days 9999 -in server.csr -signkey server.key -out server.crt
```

You'll need to upload the .crt and .key files to the cert provider. What you want back
from them is a .pem file that has their entire cert chain. Then in your bud
config set it like this:

```json
{
  "frontend": {
    // you generated this in the first step
    "key": "server.key",
    // this is the file you downloaded from your cert provider
    "cert": "server.pem"
  }
}
```

## Running as monitored process
Keep bud running even after a server restart

### SmartOS
```bash
touch bud.xml
read -d '' budconfig << EOF
<?xml version="1.0"?>
<!DOCTYPE service_bundle SYSTEM "/usr/share/lib/xml/dtd/service_bundle.dtd.1">
<!--
        Created by Manifold
--><service_bundle type="manifest" name="bud">

    <service name="bud" type="service" version="1">

        <create_default_instance enabled="true"/>

        <single_instance/>

        <dependency name="network" grouping="require_all" restart_on="error" type="service">
            <service_fmri value="svc:/milestone/network:default"/>
        </dependency>

        <dependency name="filesystem" grouping="require_all" restart_on="error" type="service">
            <service_fmri value="svc:/system/filesystem/local"/>
        </dependency>

        <exec_method type="method" name="start" exec="/opt/local/bin/bud -c %{config_file} -d" timeout_seconds="5"/>

        <exec_method type="method" name="stop" exec=":kill" timeout_seconds="60"/>

        <property_group name="startd" type="framework">

            <propval name="duration" type="astring" value="contract"/>
            <propval name="ignore_error" type="astring" value="core,signal"/>
        </property_group>


        <property_group name="application" type="application">
            <!-- TODO: customize this path to your bud config -->
            <propval name="config_file" type="astring" value="/root/bud/bud.json"/>
        </property_group>


        <stability value="Evolving"/>

        <template>
            <common_name>
                <loctext xml:lang="C">
                    bud-tls
                </loctext>
            </common_name>
        </template>

    </service>

</service_bundle>
EOF
echo $budconfig > bud.xml
svccfg import bud.xml
svcadm enable bud
# should be in the online state
svcs -l bud
# see the logs for details
tail /var/svc/log/bud\:default.log
```

### Ubuntu
A docker image is [avaliable](https://github.com/joeybaker/docker-bud-tls)

## Community

Join #bud-tls on freenode IRC to discuss things with me or others!

## LICENSE

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
[2]: https://github.com/nodejs/io.js
[3]: https://github.com/libuv/libuv
[4]: http://openssl.org/

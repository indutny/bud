var assert = require('assert');
var http = require('http');
var https = require('https');
var ocsp = require('ocsp');
var rfc2560 = require('asn1.js-rfc2560');
var spdy = require('spdy');
var utile = require('utile');
var fs = require('fs');
var path = require('path');
var url = require('url');

var bud = require('../');

var fixtures = exports;

var FRONT_PORT = 18001;
exports.FRONT_PORT = FRONT_PORT;
var BACK_PORT = 19002;
exports.BACK_PORT = BACK_PORT;

https.globalAgent._cacheSession = function() {};

function keyPath(name) {
  return path.resolve(__dirname, 'keys', name + '.pem');
}

function getKey(name) {
  return fs.readFileSync(keyPath(name)) + '';
}

fixtures.key = getKey('agent1-key');
fixtures.cert = getKey('agent1-cert');
fixtures.ca = getKey('ca1-cert');
fixtures.goodCert = getKey('good-cert');
fixtures.goodKey = getKey('good-key');
fixtures.ecCert = getKey('ec-cert');
fixtures.ecKey = getKey('ec-key');
fixtures.issuerCert = getKey('issuer-cert');
fixtures.issuerKey = getKey('issuer-key');

fixtures.keys = {
  caCert: keyPath('ca1-cert'),
  caKey: keyPath('ca1-key')
};

process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';

fixtures.getServers = function getServers(options) {
  if (!options)
    options = {};

  assert.equal(typeof beforeEach, 'function');
  assert.equal(typeof afterEach, 'function');

  var sh = {
    frontend: utile.mixin(utile.clone(options.frontend || {}), {
      host: '127.0.0.1',
      url: 'https://127.0.0.1:' + FRONT_PORT,
      port: FRONT_PORT
    }),
    backends: []
  };

  beforeEach(function(cb) {
    var backends = [];

    function addBackends(obj, out) {
      var count = obj.backends && obj.backends.length ||
                  obj.backends ||
                  1;

      for (var i = 0; i < count; i++) {
        var backend = utile.mixin({
          index: i,
          requests: 0,
          server: null,
          port: BACK_PORT++
        }, obj.backends && obj.backends[i] || {});

        !function(backend) {
          backend.server = spdy.createServer({
            plain: true,
            ssl: false
          }, function(req, res) {
            backend.requests++;
            res.setHeader('X-Backend-Id', backend.index);
            if (req.headers['x-forwarded-for']) {
              res.setHeader('X-Got-Forwarded-For',
                            req.headers['x-forwarded-for']);
            }
            if (req.headers['x-forwarded-proto']) {
              res.setHeader('X-Got-Forwarded-Proto',
                            req.headers['x-forwarded-proto']);
            }
            if (req.url === '/hello')
              res.end('hello world');
            else
              res.end('nay');
          });

          if (backend.proxyline)
            expectProxyline(backend.server, backend.proxyline);
        }(backend);
        out.push(backend);
        backends.push(backend);
      }
    }

    sh.backends = [];
    addBackends(options, sh.backends);
    if (options.contexts) {
      sh.contexts = options.contexts.map(function(context) {
        var out = [];
        addBackends(context, out);
        context.backends = out;
        return context;
      });
    }

    sh.frontend.server = bud.createServer({
      log: options.log,
      master_ipc: options.master_ipc,
      frontend: utile.filter(sh.frontend, function(val, key) {
        return !/^(server|url|host|port)$/.test(key);
      }),
      backend: sh.backends.map(function(backend) {
        return utile.filter(backend, function(val, key) {
          return !/^(server|requests|index)$/.test(key);
        });
      }),
      stapling: options.stapling,
      sni: options.sni,
      balance: options.balance,
      contexts: sh.contexts && sh.contexts.map(function(ctx) {
        return {
          servername: ctx.servername,
          key: ctx.key,
          cert: ctx.cert,
          backend: ctx.backends.map(function(backend) {
            return utile.filter(backend, function(val, key) {
              return !/^(server|requests|index)$/.test(key);
            });
          })
        };
      })
    });

    sh.frontend.server.listen(FRONT_PORT, function() {
      utile.async.each(backends, function(backend, cb) {
        backend.server.listen(backend.port, cb);
      }, cb);
    });
  });

  afterEach(function(cb) {
    sh.frontend.server.close(function() {
      utile.async.each(sh.backends, function(backend, cb) {
        backend.server.close(cb);
      }, cb);
    });
  });

  return sh;
};

fixtures.request = function request(sh, uri, cb) {
  https.get(sh.frontend.url + uri, function(res) {
    var chunks = '';
    res.on('readable', function() {
      chunks += res.read() || '';
    });
    res.on('end', function() {
      cb(res, chunks);
    });
  });
};

fixtures.caRequest = function caRequest(sh, uri, fake, cb) {
  var o = url.parse(sh.frontend.url + uri);
  o.agent = new https.Agent({
    key: fixtures.key,
    cert: fixtures.cert
  });
  https.get(o, function(res) {
    var chunks = '';
    res.on('readable', function() {
      chunks += res.read() || '';
    });
    res.on('end', function() {
      cb(res, chunks);
    });
  });
};

fixtures.sniRequest = function sniRequest(sh, name, uri, cb) {
  var o = url.parse(sh.frontend.url + uri);
  o.agent = new https.Agent({
  });
  var createConn = o.agent.createConnection;
  o.agent.createConnection = function createConnection(options) {
    options.servername = name;
    return createConn.call(this, options);
  };
  https.get(o, function(res) {
    var chunks = '';
    var info = {
      cert: res.socket.getPeerCertificate(true),
      cipher: res.socket.getCipher()
    };
    res.on('readable', function() {
      chunks += res.read() || '';
    });
    res.on('end', function() {
      cb(res, chunks, info);
    });
  });
};

fixtures.spdyRequest = function spdyRequest(sh, uri, cb) {
  var agent = spdy.createAgent(sh.frontend);
  return fixtures.agentRequest(sh, agent, uri, cb);
};

fixtures.agentRequest = function agentRequest(sh, agent, uri, cb) {
  var req = https.request({
    agent: agent,
    path: uri,
    session: null
  }, function(res) {
    var chunks = '';
    var info = {
      cert: res.socket.getPeerCertificate(true),
      cipher: res.socket.getCipher()
    };
    res.on('readable', function() {
      chunks += res.read() || '';
    });
    res.on('end', function() {
      if (!agent.close)
        return cb(res, chunks, info);

      agent.close(function() {
        cb(res, chunks, info);
      });
    });
  });
  req.end();
};

function expectProxyline(server, type) {
  var listeners = server.listeners('connection').slice();
  server.removeAllListeners('connection');

  server.on('connection', function(s) {
    var chunks = '';
    s.on('readable', function onReadable() {
      var chunk = this.read();
      if (!chunk)
        return;

      chunks += chunk;
      assert(chunks.length < 1024);
      if (type === true || type === 'haproxy') {
        var match = chunks.match(
          /^PROXY (TCP\d) ([^\r\s]+) ([^\r\s]+) ([^\r\s]+) ([^\r\s]+)\r\n/
        );
        if (!match)
          return;
        var line = {
          protocol: match[1],
          outbound: {
            host: match[2],
            port: match[4],
            cn: ''
          },
          inbound: {
            host: match[3],
            port: match[5],
          }
        };
      } else {
        var match = chunks.match(
          /^BUD ([^\r\n]+)\r\n/
        );
        if (!match)
          return;

        var j = JSON.parse(match[1]);
        var line = {
          protocol: j.family,
          outbound: {
            host: j.peer.host,
            port: j.peer.port,
            cn: j.peer.cn
          },
          inbound: {
            host: j.bud.host,
            port: j.bud.port
          }
        };
      }

      s.removeListener('readable', onReadable);
      var rest = new Buffer(chunks.slice(match[0].length));
      if (rest.length !== 0)
        s.unshift(rest);

      server.emit('proxyline', line);
      listeners[0].call(server, s);
      s.emit('readable');
    });
  });
}

fixtures.ocspBackend = function ocspBackend() {
  var cache = {};

  var ocspServer = ocsp.Server.create({
    cert: fixtures.issuerCert,
    key: fixtures.issuerKey
  });

  ocspServer.addCert(43, 'good');
  ocspServer.addCert('ff998c4ccfc2c839', 'good');
  ocspServer.addCert(44, 'revoked', {
    revocationTime: new Date(),
    revocationReason: 'CACompromise'
  });

  var server = http.createServer(function(req, res) {
    var id = req.url.split('/')[3];
    if (req.method === 'GET' && cache[id]) {
      res.writeHead(200, {
        'Content-Type': 'application/json'
      });
      server.cacheHits++;
      return res.end(JSON.stringify(cache[id]));
    }

    if (req.method === 'GET') {
      res.writeHead(404, {
        'Content-Type': 'application/json'
      });
      return res.end('{}');
    }

    server.cacheMisses++;
    var chunks = '';
    req.on('data', function(chunk) {
      chunks += chunk;
    });
    req.once('end', function() {
      var body = JSON.parse(chunks);
      var ocspReq = rfc2560.OCSPRequest.decode(
          new Buffer(body.ocsp, 'base64'),
          'der');

      ocspServer.getResponses(ocspReq, function(err, responses) {
        if (err)
          throw err;

        res.writeHead(200, { 'Content-Type': 'application/json' });
        var out = {
          response: responses.toString('base64')
        };
        cache[id] = out;
        res.end(JSON.stringify(out));
      });
    });
  });

  server.cacheHits = 0;
  server.cacheMisses = 0;

  return server;
};

fixtures.sniBackend = function sniBackend() {
  var server = http.createServer(function(req, res) {
    var host = req.url.split('/')[3];
    if (host !== 'sni.host') {
      server.misses++;
      res.writeHead(404, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: true, reason: 'SNI ctx not found' }));
      return;
    }

    server.hits++;
    res.writeHead(200, { 'Content-Type': 'application/json' });
    var out = {
      cert: fixtures.goodCert + '\n' + fixtures.issuerCert,
      key: fixtures.goodKey,
      ciphers: 'AES128-SHA'
    };
    res.end(JSON.stringify(out));
  });

  server.hits = 0;
  server.misses = 0;

  return server;
};

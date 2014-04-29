var assert = require('assert');
var https = require('https');
var spdy = require('spdy');
var utile = require('utile');

var bud = require('../');

var fixtures = exports;

var FRONT_PORT = 18001;
var BACK_PORT = 18002;

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
    var count = options.backends && options.backends.length ||
                options.backends ||
                1;

    sh.backends = [];
    for (var i = 0; i < count; i++) {
      var backend = utile.mixin({
        index: i,
        requests: 0,
        server: null,
        port: BACK_PORT + i
      }, options.backends && options.backends[i] || {});

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
          if (req.url === '/hello')
            res.end('hello world');
          else
            res.end('nay');
        });

        if (backend.proxyline)
          expectProxyline(backend.server);
      }(backend);
      sh.backends.push(backend);
    }

    sh.frontend.server = bud.createServer({
      frontend: utile.filter(sh.frontend, function(val, key) {
        return !/^(server|url|host|port)$/.test(key);
      }),
      backend: sh.backends.map(function(backend) {
        return utile.filter(backend, function(val, key) {
          return !/^(server|requests|index)$/.test(key);
        });
      })
    });

    sh.frontend.server.listen(FRONT_PORT, function() {
      utile.async.each(sh.backends, function(backend, cb) {
        backend.server.listen(backend.port, cb);
      }, cb);
    });
  });

  afterEach(function(cb) {
    utile.async.each(sh.backends, function(backend, cb) {
      backend.server.close(cb);
    }, function() {
      sh.frontend.server.close(cb);
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

fixtures.caRequest = function caRequest(sh, uri, cb) {
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

fixtures.spdyRequest = function spdyRequest(sh, uri, cb) {
  var agent = spdy.createAgent(sh.frontend);

  var req = https.request({
    agent: agent,
    path: uri
  }, function(res) {
    var chunks = '';
    res.on('readable', function() {
      chunks += res.read() || '';
    });
    res.on('end', function() {
      agent.close(function() {
        cb(res, chunks);
      });
    });
  });
  req.end();
};

function expectProxyline(server) {
  server.on('connection', function(s) {
    var ondata = s.ondata;
    var chunks = '';
    s.ondata = function _ondata(c, start, end) {
      chunks += c.slice(start, end);
      assert(chunks.length < 1024);
      var match = chunks.match(
        /^PROXY (TCP\d) ([^\s]+) ([^\s]+) ([^\s]+) ([^\s]+)\r\n/
      );
      if (!match)
        return;

      server.emit('proxyline', {
        protocol: match[1],
        outbound: {
          host: match[2],
          port: match[4]
        },
        inbound: {
          host: match[3],
          port: match[5]
        }
      });
      s.ondata = ondata;

      var rest = new Buffer(chunks.slice(match[0].length));
      if (rest.length !== 0)
        ondata.call(this, rest, 0, rest.length);
    };
  });
}

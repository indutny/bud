var assert = require('assert');
var http = require('http');
var https = require('https');
var utile = require('utile');

var bud = require('../');

var fixtures = exports;

var FRONT_PORT = 18001;
var BACK_PORT = 18002;

fixtures.getServers = function getServers(options) {
  if (!options)
    options = {};

  assert.equal(typeof beforeEach, 'function');
  assert.equal(typeof afterEach, 'function');

  var sh = {
    frontend: {
      url: 'https://127.0.0.1:' + FRONT_PORT
    },
    backends: []
  };

  beforeEach(function(cb) {
    var count = options.backends && options.backends.length ||
                options.backends ||
                1;
    for (var i = 0; i < count; i++) {
      var backend = {
        index: i,
        requests: 0,
        server: null,
        port: BACK_PORT + i
      };

      !function(backend) {
        backend.server = http.createServer(function(req, res) {
          backend.requests++;
          res.setHeader('X-Backend-Id', backend.index);
          if (req.url === '/hello')
            res.end('hello world');
          else
            res.end('nay');
        });
      }(backend);
      sh.backends.push(backend);
    }

    sh.frontend.server = bud.createServer({
      backend: sh.backends.map(function(backend, i) {
        return utile.mixin({ port: backend.port },
                           options.backends && options.backends[i] || {});
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

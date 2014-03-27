var assert = require('assert');
var http = require('http');

var bud = require('../');

var fixtures = exports;

var FRONT_PORT = 18001;
var BACK_PORT = 18002;

fixtures.getServers = function getServers(options) {
  assert.equal(typeof beforeEach, 'function');
  assert.equal(typeof afterEach, 'function');

  var sh = {
    frontend: {
      url: 'https://127.0.0.1:' + FRONT_PORT
    },
    backend: {
      requests: 0
    }
  };

  beforeEach(function(cb) {
    sh.backend.requests = 0;

    sh.backend.server = http.createServer(function(req, res) {
      sh.backend.requests++;
      if (req.url === '/hello')
        res.end('hello world');
      else
        res.end('nay');
    });

    sh.frontend.server = bud.createServer({
      backend: [{
        port: BACK_PORT
      }]
    });

    sh.frontend.server.listen(FRONT_PORT, function() {
      sh.backend.server.listen(BACK_PORT, cb);
    });
  });

  afterEach(function(cb) {
    sh.backend.server.close(function() {
      sh.frontend.server.close(cb);
    });
  });

  return sh;
};

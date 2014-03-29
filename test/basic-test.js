var assert = require('assert');
var fixtures = require('./fixtures');
var request = fixtures.request;

process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';

describe('Bud TLS Terminator', function() {
  describe('single backend', function() {
    var sh = fixtures.getServers();

    it('should support basic termination', function(cb) {
      request(sh, '/hello', function(res, body) {
        assert.equal(sh.backends[0].requests, 1);
        assert.equal(res.statusCode, 200);
        assert.equal(res.headers['x-backend-id'], 0);
        assert.equal(body, 'hello world');
        cb();
      });
    });
  });

  describe('multi-backend', function() {
    var sh = fixtures.getServers({ backends: 2 });

    it('should support round-robin balancing', function(cb) {
      request(sh, '/hello', function(res, body) {
        assert.equal(sh.backends[0].requests, 1);
        assert.equal(res.headers['x-backend-id'], 0);
        request(sh, '/hello', function(res, body) {
          assert.equal(sh.backends[1].requests, 1);
          assert.equal(res.headers['x-backend-id'], 1);
          request(sh, '/hello', function(res, body) {
            assert.equal(sh.backends[0].requests, 2);
            assert.equal(res.headers['x-backend-id'], 0);
            cb();
          });
        });
      });
    });
  });

  describe('proxyline', function() {
    var sh = fixtures.getServers({
      backends: [{
        proxyline: true
      }]
    });

    it('should support round-robin balancing', function(cb) {
      var gotProxyline = false;

      request(sh, '/hello', function(res, body) {
        assert.equal(sh.backends[0].requests, 1);
        assert(gotProxyline);
        cb();
      });

      sh.backends[0].server.on('proxyline', function(obj) {
        assert.equal(obj.inbound.port, sh.frontend.port);
        gotProxyline = true;
      });
    });
  });
});

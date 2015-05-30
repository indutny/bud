var assert = require('assert');
var fixtures = require('./fixtures');
var request = fixtures.request;
var caRequest = fixtures.caRequest;
var sniRequest = fixtures.sniRequest;
var spdyRequest = fixtures.spdyRequest;

describe('Bud TLS Terminator/Basic', function() {
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

  describe('single backend with passphrase', function() {
    var sh = fixtures.getServers({
      log: {
        level: 'debug'
      },
      frontend: {
        key: fixtures.keys.caKey,
        cert: fixtures.keys.caCert,
        passphrase: 'password'
      }
    });

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
});

var assert = require('assert');
var fixtures = require('./fixtures');
var request = fixtures.request;
var caRequest = fixtures.caRequest;
var spdyRequest = fixtures.spdyRequest;

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

    it('should work', function(cb) {
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

  describe('x-forward', function() {
    var sh = fixtures.getServers({
      frontend: {
        npn: [ 'spdy/3.1' , 'spdy/3' , 'spdy/2' , 'http/1.1' ]
      },
      backends: [{
        'x-forward': true
      }]
    });

    it('should work with http', function(cb) {
      request(sh, '/hello', function(res, body) {
        assert.equal(sh.backends[0].requests, 1);
        assert.equal(res.headers['x-got-forwarded-for'], '127.0.0.1');
        cb();
      });
    });

    it('should work with spdy', function(cb) {
      spdyRequest(sh, '/hello', function(res, body) {
        assert.equal(sh.backends[0].requests, 1);
        assert.equal(res.headers['x-got-forwarded-for'], '127.0.0.1');
        cb();
      });
    });
  });

  describe('request cert and JSON proxyline', function() {
    var sh = fixtures.getServers({
      frontend: {
        request_cert: true,
        ca: [ fixtures.ca ]
      },
      backends: [{
        proxyline: 'json'
      }]
    });

    it('should request and validate cert', function(cb) {
      caRequest(sh, '/hello', false, function(res, body) {
        assert.equal(sh.backends[0].requests, 1);
        assert(gotProxyline);
        cb();
      });
      var gotProxyline = false;

      sh.backends[0].server.on('proxyline', function(obj) {
        assert.equal(obj.inbound.port, sh.frontend.port);
        assert(/agent1/.test(obj.outbound.cn));
        gotProxyline = true;
      });
    });
  });
});

var assert = require('assert');
var fixtures = require('./fixtures');
var request = fixtures.request;
var caRequest = fixtures.caRequest;
var sniRequest = fixtures.sniRequest;
var spdyRequest = fixtures.spdyRequest;

describe('Bud TLS Terminator/Proxyline', function() {
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

  describe('JSON proxyline', function() {
    var sh = fixtures.getServers({
      frontend: {
      },
      backends: [{
        proxyline: 'json'
      }]
    });

    it('should return empty cn cert', function(cb) {
      request(sh, '/hello', function(res, body) {
        assert.equal(sh.backends[0].requests, 1);
        assert(gotProxyline);
        cb();
      });
      var gotProxyline = false;

      sh.backends[0].server.on('proxyline', function(obj) {
        assert.equal(obj.inbound.port, sh.frontend.port);
        assert.equal(false, obj.outbound.cn);
        gotProxyline = true;
      });
    });
  });

  describe('JSON proxyline', function() {
    var sh = fixtures.getServers({
      frontend: {
      },
      backends: [{
        proxyline: 'json'
      }]
    });

    it('should return empty cn cert', function(cb) {
      request(sh, '/hello', function(res, body) {
        assert.equal(sh.backends[0].requests, 1);
        assert(gotProxyline);
        cb();
      });
      var gotProxyline = false;

      sh.backends[0].server.on('proxyline', function(obj) {
        assert.equal(obj.inbound.port, sh.frontend.port);
        assert.equal(false, obj.outbound.cn);
        gotProxyline = true;
      });
    });
  });
});

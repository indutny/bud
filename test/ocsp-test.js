var assert = require('assert');
var fixtures = require('./fixtures');
var ocsp = require('ocsp');
var request = fixtures.request;
var caRequest = fixtures.caRequest;
var sniRequest = fixtures.sniRequest;
var spdyRequest = fixtures.spdyRequest;
var agentRequest = fixtures.agentRequest;

describe('Bud TLS Terminator/OCSP', function() {
  var sh = fixtures.getServers({
    frontend: {
      key: fixtures.goodKey,
      cert: fixtures.goodCert + '\n' + fixtures.issuerCert
    },
    stapling: {
      enabled: true,
      port: 9000
    }
  });

  var ocspBackend;
  beforeEach(function(cb) {
    ocspBackend = fixtures.ocspBackend().listen(9000, cb);
  });

  afterEach(function(cb) {
    ocspBackend.close(cb);
  });

  var agent = new ocsp.Agent({
    port: sh.frontend.port
  });

  it('should work', function(cb) {
    agentRequest(sh, agent, '/hello', function(res, body) {
      assert.equal(sh.backends[0].requests, 1);
      assert.equal(ocspBackend.cacheHits, 0);
      assert.equal(ocspBackend.cacheMisses, 1);
      cb();
    });
  });

  it('should use cached results', function(cb) {
    agentRequest(sh, agent, '/hello', function(res, body) {
      agentRequest(sh, agent, '/hello', function(res, body) {
        assert.equal(sh.backends[0].requests, 2);
        assert.equal(ocspBackend.cacheHits, 1);
        assert.equal(ocspBackend.cacheMisses, 1);
        cb();
      });
    });
  });
});

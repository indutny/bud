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
      key: [
        fixtures.goodKey,
        fixtures.ecKey
      ],
      cert: [
        fixtures.goodCert + '\n' + fixtures.issuerCert,
        fixtures.ecCert + '\n' + fixtures.issuerCert
      ]
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
    port: sh.frontend.port,
    ciphers: 'RSA'
  });

  it('should work', function(cb) {
    agentRequest(sh, agent, '/hello', function(res, body, info) {
      assert(!/ECDSA/i.test(info.cipher.name));
      assert.equal(sh.backends[0].requests, 1);
      assert.equal(ocspBackend.cacheHits, 0);
      assert.equal(ocspBackend.cacheMisses, 1);
      cb();
    });
  });

  it('should use cached results', function(cb) {
    agentRequest(sh, agent, '/hello', function(res, body) {
      agentRequest(sh, agent, '/hello', function(res, body, info) {
        assert(!/ECDSA/i.test(info.cipher.name));
        assert.equal(sh.backends[0].requests, 2);
        assert.equal(ocspBackend.cacheHits, 1);
        assert.equal(ocspBackend.cacheMisses, 1);
        cb();
      });
    });
  });

  it('should get ECC OCSP stapling', function(cb) {
    var eccAgent = new ocsp.Agent({
      port: sh.frontend.port,
      cipher: 'ECDSA'
    });

    agentRequest(sh, eccAgent, '/hello', function(res, body, info) {
      assert(/ECDSA/i.test(info.cipher.name));
      assert.equal(sh.backends[0].requests, 1);
      assert.equal(ocspBackend.cacheHits, 0);
      assert.equal(ocspBackend.cacheMisses, 1);
      cb();
    });
  });
});

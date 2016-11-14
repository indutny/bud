'use strict';

const assert = require('assert');
const fixtures = require('./fixtures');
const ocsp = require('ocsp');
const request = fixtures.request;
const caRequest = fixtures.caRequest;
const sniRequest = fixtures.sniRequest;
const spdyRequest = fixtures.spdyRequest;
const agentRequest = fixtures.agentRequest;

describe('Bud TLS Terminator/OCSP', () => {
  const sh = fixtures.getServers({
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

  let ocspBackend;
  beforeEach((cb) => {
    ocspBackend = fixtures.ocspBackend().listen(9000, cb);
  });

  afterEach((cb) => {
    ocspBackend.close(cb);
  });

  const agent = new ocsp.Agent({
    port: sh.frontend.port,
    ciphers: 'RSA'
  });

  it('should work', (cb) => {
    agentRequest(sh, agent, '/hello', (res, body, info) => {
      assert(!/ECDSA/i.test(info.cipher.name));
      assert.equal(sh.backends[0].requests, 1);
      assert.equal(ocspBackend.cacheHits, 0);
      assert.equal(ocspBackend.cacheMisses, 1);
      cb();
    });
  });

  it('should use cached results', (cb) => {
    agentRequest(sh, agent, '/hello', (res, body) => {
      agentRequest(sh, agent, '/hello', (res, body, info) => {
        assert(!/ECDSA/i.test(info.cipher.name));
        assert.equal(sh.backends[0].requests, 2);
        assert.equal(ocspBackend.cacheHits, 1);
        assert.equal(ocspBackend.cacheMisses, 1);
        cb();
      });
    });
  });

  it('should get ECC OCSP stapling', (cb) => {
    const eccAgent = new ocsp.Agent({
      port: sh.frontend.port,
      cipher: 'ECDSA'
    });

    agentRequest(sh, eccAgent, '/hello', (res, body, info) => {
      assert(/ECDSA/i.test(info.cipher.name));
      assert.equal(sh.backends[0].requests, 1);
      assert.equal(ocspBackend.cacheHits, 0);
      assert.equal(ocspBackend.cacheMisses, 1);
      cb();
    });
  });
});

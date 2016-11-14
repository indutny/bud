'use strict';

const assert = require('assert');
const fixtures = require('./fixtures');
const ocsp = require('ocsp');
const request = fixtures.request;
const caRequest = fixtures.caRequest;
const sniRequest = fixtures.sniRequest;
const spdyRequest = fixtures.spdyRequest;
const agentRequest = fixtures.agentRequest;

describe('Bud TLS Terminator/SNI', () => {
  describe('multi-backend', () => {
    const sh = fixtures.getServers({
      balance: 'sni',
      contexts: [{
        servername: 'local.host',
        backends: 2
      }]
    });

    it('should support round-robin balancing', (cb) => {
      const ctx = sh.contexts[0];
      let count = 20;
      const stats = [];
      function fire(cb) {
        if (--count === 0)
          return cb();

        sniRequest(sh, 'local.host', '/hello', (res) => {
          stats.push({
            backends: ctx.backends.map((back) => {
              return back.requests;
            }),
            id: res.headers['x-backend-id'] | 0
          });
          fire(cb);
        });
      }

      fire(() => {
        const check = ctx.backends.map(() => {
          return 0;
        });

        for (let i = 0; i < stats.length; i++) {
          check[stats[i].id]++;
          assert.deepEqual(check, stats[i].backends);
        }

        cb();
      });
    });
  });

  [ true, false ].forEach((keepalive) => {
    describe('async sni with keepalive=' + keepalive, () => {
      const sh = fixtures.getServers({
        sni: {
          enabled: true,
          port: 9000
        }
      });

      let sniBackend;
      beforeEach((cb) => {
        sniBackend = fixtures.sniBackend({
          keepalive: keepalive
        }).listen(9000, cb);
      });

      afterEach((cb) => {
        sniBackend.close(cb);
      });

      it('should asynchronously fetch cert', (cb) => {
        sniRequest(sh, 'local.host', '/hello', (res, chunks, info) => {
          assert.equal(sniBackend.misses, 1);
          assert.equal(sniBackend.hits, 0);
          assert.equal(info.cert.serialNumber, '82F2A828A42C1728');
          assert.notEqual(info.cipher.name, 'AES128-SHA');

          sniRequest(sh, 'sni.host', '/hello', (res, chunks, info) => {
            assert.equal(sniBackend.misses, 1);
            assert.equal(sniBackend.hits, 1);
            assert.equal(info.cert.serialNumber, '2B');
            assert.equal(info.cipher.name, 'AES128-SHA');
            cb();
          });
        });
      });

      it('should survive stress test', (cb) => {
        function stress(count, cb) {
          function fire(cb) {
            if (--count === 0)
              return cb();

            sniRequest(sh, 'local.host', '/hello', () => {
              fire(cb);
            });
          }

          fire(cb);
        }

        let waiting = 10;
        for (let i = 0; i < waiting; i++)
          stress(10, done);

        function done() {
          if (--waiting === 0)
            cb();
        }
      });
    });
  });

  describe('async sni+ocsp', () => {
    const sh = fixtures.getServers({
      log: { level: 'debug' },
      sni: {
        enabled: true,
        port: 9000
      },
      stapling: {
        enabled: true,
        port: 9001
      }
    });

    let sniBackend;
    let ocspBackend;
    beforeEach((cb) => {
      sniBackend = fixtures.sniBackend().listen(9000, () => {
        ocspBackend = fixtures.ocspBackend().listen(9001, cb);
      });
    });

    afterEach((cb) => {
      sniBackend.close(() => {
        ocspBackend.close(cb);
      });
    });

    it('should asynchronously fetch cert', (cb) => {
      const agent = new ocsp.Agent({
        port: sh.frontend.port,
        servername: 'sni.host'
      });

      // Nasty hack for node.js v0.12
      const createConn = agent.createConnection;
      agent.createConnection = function createConnection(options) {
        options.servername = 'sni.host';
        return createConn.call(this, options);
      };

      agentRequest(sh, agent, '/hello', (res, chunks, info) => {
        assert.equal(sniBackend.misses, 0);
        assert.equal(sniBackend.hits, 1);
        assert.equal(ocspBackend.cacheHits, 0);
        assert.equal(ocspBackend.cacheMisses, 1);

        assert.equal(info.cert.serialNumber, '2B');
        assert.equal(info.cipher.name, 'AES128-SHA');
        cb();
      });
    });
  });

  describe('sync sni+ocsp', () => {
    const sh = fixtures.getServers({
      contexts: [{
        servername: 'local.host',
        cert: fixtures.goodCert + '\n' + fixtures.issuerCert,
        key: fixtures.goodKey
      }],
      stapling: {
        enabled: true,
        port: 9001
      }
    });

    let ocspBackend;
    beforeEach((cb) => {
      ocspBackend = fixtures.ocspBackend().listen(9001, cb);
    });

    afterEach((cb) => {
      ocspBackend.close(cb);
    });

    it('should still provide stapling response', (cb) => {
      const agent = new ocsp.Agent({
        port: sh.frontend.port,
        servername: 'local.host'
      });

      // Nasty hack for node.js v0.12
      const createConn = agent.createConnection;
      agent.createConnection = function createConnection(options) {
        options.servername = 'local.host';
        return createConn.call(this, options);
      };

      agentRequest(sh, agent, '/hello', (res, chunks, info) => {
        assert.equal(ocspBackend.cacheHits, 0);
        assert.equal(ocspBackend.cacheMisses, 1);

        assert.equal(info.cert.serialNumber, '2B');
        cb();
      });
    });
  });
});

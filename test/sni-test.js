var assert = require('assert');
var fixtures = require('./fixtures');
var ocsp = require('ocsp');
var request = fixtures.request;
var caRequest = fixtures.caRequest;
var sniRequest = fixtures.sniRequest;
var spdyRequest = fixtures.spdyRequest;
var agentRequest = fixtures.agentRequest;

describe('Bud TLS Terminator/SNI', function() {
  describe('multi-backend', function() {
    var sh = fixtures.getServers({
      balance: 'sni',
      contexts: [{
        servername: 'local.host',
        backends: 2
      }]
    });

    it('should support round-robin balancing', function(cb) {
      var ctx = sh.contexts[0];
      var count = 20;
      var stats = [];
      function fire(cb) {
        if (--count === 0)
          return cb();

        sniRequest(sh, 'local.host', '/hello', function(res) {
          stats.push({
            backends: ctx.backends.map(function(back) {
              return back.requests;
            }),
            id: res.headers['x-backend-id'] | 0
          });
          fire(cb);
        });
      }

      fire(function() {
        var check = ctx.backends.map(function() {
          return 0;
        });

        for (var i = 0; i < stats.length; i++) {
          check[stats[i].id]++;
          assert.deepEqual(check, stats[i].backends);
        }

        cb();
      });
    });
  });

  describe('async sni', function() {
    var sh = fixtures.getServers({
      sni: {
        enabled: true,
        port: 9000
      }
    });

    var sniBackend;
    beforeEach(function(cb) {
      sniBackend = fixtures.sniBackend().listen(9000, cb);
    });

    afterEach(function(cb) {
      sniBackend.close(cb);
    });

    it('should asynchronously fetch cert', function(cb) {
      sniRequest(sh, 'local.host', '/hello', function(res, chunks, info) {
        assert.equal(sniBackend.misses, 1);
        assert.equal(sniBackend.hits, 0);
        assert.equal(info.cert.serialNumber, '82F2A828A42C1728');
        assert.notEqual(info.cipher.name, 'AES128-SHA');

        sniRequest(sh, 'sni.host', '/hello', function(res, chunks, info) {
          assert.equal(sniBackend.misses, 1);
          assert.equal(sniBackend.hits, 1);
          assert.equal(info.cert.serialNumber, '2B');
          assert.equal(info.cipher.name, 'AES128-SHA');
          cb();
        });
      });
    });
  });

  describe('async sni+ocsp', function() {
    var sh = fixtures.getServers({
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

    var sniBackend;
    var ocspBackend;
    beforeEach(function(cb) {
      sniBackend = fixtures.sniBackend().listen(9000, function() {
        ocspBackend = fixtures.ocspBackend().listen(9001, cb);
      });
    });

    afterEach(function(cb) {
      sniBackend.close(function() {
        ocspBackend.close(cb);
      });
    });

    it('should asynchronously fetch cert', function(cb) {
      var agent = new ocsp.Agent({
        port: sh.frontend.port,
        servername: 'sni.host'
      });

      // Nasty hack for node.js v0.12
      var createConn = agent.createConnection;
      agent.createConnection = function createConnection(options) {
        options.servername = 'sni.host';
        return createConn.call(this, options);
      };

      agentRequest(sh, agent, '/hello', function(res, chunks, info) {
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

  describe('sync sni+ocsp', function() {
    var sh = fixtures.getServers({
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

    var ocspBackend;
    beforeEach(function(cb) {
      ocspBackend = fixtures.ocspBackend().listen(9001, cb);
    });

    afterEach(function(cb) {
      ocspBackend.close(cb);
    });

    it('should still provide stapling response', function(cb) {
      var agent = new ocsp.Agent({
        port: sh.frontend.port,
        servername: 'local.host'
      });

      // Nasty hack for node.js v0.12
      var createConn = agent.createConnection;
      agent.createConnection = function createConnection(options) {
        options.servername = 'local.host';
        return createConn.call(this, options);
      };

      agentRequest(sh, agent, '/hello', function(res, chunks, info) {
        assert.equal(ocspBackend.cacheHits, 0);
        assert.equal(ocspBackend.cacheMisses, 1);

        assert.equal(info.cert.serialNumber, '2B');
        cb();
      });
    });
  });
});

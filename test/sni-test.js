var assert = require('assert');
var fixtures = require('./fixtures');
var request = fixtures.request;
var caRequest = fixtures.caRequest;
var sniRequest = fixtures.sniRequest;
var spdyRequest = fixtures.spdyRequest;

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

    var sniServer;
    beforeEach(function(cb) {
      sniServer = fixtures.sniServer().listen(9000, cb);
    });

    afterEach(function(cb) {
      sniServer.close(cb);
    });

    it('should asynchronously fetch cert', function(cb) {
      sniRequest(sh, 'local.host', '/hello', function(res, chunks, info) {
        assert.equal(sniServer.misses, 1);
        assert.equal(sniServer.hits, 0);
        assert.equal(info.cert.serialNumber, '82F2A828A42C1728');
        assert.notEqual(info.cipher.name, 'AES128-SHA');

        sniRequest(sh, 'sni.host', '/hello', function(res, chunks, info) {
          assert.equal(sniServer.misses, 1);
          assert.equal(sniServer.hits, 1);
          assert.equal(info.cert.serialNumber, '2B');
          assert.equal(info.cipher.name, 'AES128-SHA');
          cb();
        });
      });
    });
  });
});

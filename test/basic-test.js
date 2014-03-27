var assert = require('assert');
var fixtures = require('./fixtures');
var https = require('https');

process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';

describe('Bud TLS Terminator', function() {
  var sh = fixtures.getServers();

  it('should support basic termination', function(cb) {
    https.get(sh.frontend.url + '/hello', function(res) {
      assert.equal(sh.backend.requests, 1);
      assert.equal(res.statusCode, 200);

      var chunks = '';
      res.on('readable', function() {
        chunks += res.read() || '';
      });
      res.on('end', function() {
        assert.equal(chunks, 'hello world');
        cb();
      });
    });
  });
});

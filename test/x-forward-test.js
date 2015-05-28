var assert = require('assert');
var fixtures = require('./fixtures');
var request = fixtures.request;
var caRequest = fixtures.caRequest;
var sniRequest = fixtures.sniRequest;
var spdyRequest = fixtures.spdyRequest;

describe('Bud TLS Terminator/x-forward', function() {
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
      assert.equal(res.headers['x-got-forwarded-proto'], 'https');
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

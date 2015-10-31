var assert = require('assert');
var fixtures = require('./fixtures');
var request = fixtures.request;
var malformedRequest = fixtures.malformedRequest;
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

  it('should work with LF-only http', function(cb) {
    malformedRequest(sh, '/hello', function(body) {
      assert.equal(sh.backends[0].requests, 1);
      assert(/X-Got-Forwarded-For: 127.0.0.1/.test(body));
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

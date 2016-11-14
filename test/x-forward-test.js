'use strict';

const assert = require('assert');
const fixtures = require('./fixtures');
const request = fixtures.request;
const malformedRequest = fixtures.malformedRequest;
const spdyRequest = fixtures.spdyRequest;

describe('Bud TLS Terminator/x-forward', () => {
  const sh = fixtures.getServers({
    frontend: {
      npn: [ 'spdy/3.1' , 'spdy/3' , 'spdy/2' , 'http/1.1' ]
    },
    backends: [{
      'x-forward': true
    }]
  });

  it('should work with http', (cb) => {
    request(sh, '/hello', (res, body) => {
      assert.equal(sh.backends[0].requests, 1);
      assert.equal(res.headers['x-got-forwarded-for'], '127.0.0.1');
      assert.equal(res.headers['x-got-forwarded-proto'], 'https');
      cb();
    });
  });

  it('should work with LF-only http', (cb) => {
    malformedRequest(sh, '/hello', (body) => {
      assert.equal(sh.backends[0].requests, 1);
      assert(/X-Got-Forwarded-For: 127.0.0.1/.test(body));
      cb();
    });
  });

  it('should work with spdy', (cb) => {
    spdyRequest(sh, '/hello', (res, body) => {
      assert.equal(sh.backends[0].requests, 1);
      assert.equal(res.headers['x-got-forwarded-for'], '127.0.0.1');
      cb();
    });
  });
});

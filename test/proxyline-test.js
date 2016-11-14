'use strict';

const assert = require('assert');
const fixtures = require('./fixtures');
const request = fixtures.request;
const caRequest = fixtures.caRequest;
const sniRequest = fixtures.sniRequest;
const spdyRequest = fixtures.spdyRequest;
const renegRequest = fixtures.renegRequest;

describe('Bud TLS Terminator/Proxyline', () => {
  describe('proxyline', () => {
    const sh = fixtures.getServers({
      backends: [{
        proxyline: true
      }]
    });

    it('should work', (cb) => {
      let gotProxyline = false;

      request(sh, '/hello', (res, body) => {
        assert.equal(sh.backends[0].requests, 1);
        assert(gotProxyline);
        cb();
      });

      sh.backends[0].server.on('proxyline', (obj) => {
        assert.equal(obj.inbound.port, sh.frontend.port);
        gotProxyline = true;
      });
    });

    it('should not be sent twice on renegotiation', (cb) => {
      let gotProxyline = 0;

      renegRequest(sh, '/hello', () => {
        assert.equal(sh.backends[0].requests, 1);
        assert.equal(gotProxyline, 1);
        cb();
      });

      sh.backends[0].server.on('proxyline', (obj) => {
        assert.equal(obj.inbound.port, sh.frontend.port);
        gotProxyline++;
      });
    });
  });

  describe('request cert and JSON proxyline', () => {
    const sh = fixtures.getServers({
      frontend: {
        request_cert: true,
        ca: [ fixtures.ca ]
      },
      backends: [{
        proxyline: 'json'
      }]
    });

    it('should request and validate cert', (cb) => {
      caRequest(sh, '/hello', false, (res, body) => {
        assert.equal(sh.backends[0].requests, 1);
        assert(gotProxyline);
        cb();
      });
      let gotProxyline = false;

      sh.backends[0].server.on('proxyline', (obj) => {
        assert.equal(obj.inbound.port, sh.frontend.port);
        assert(/agent1/.test(obj.outbound.cn));
        assert(/distinguished-agent1/.test(obj.outbound.dn));
        gotProxyline = true;
      });
    });
  });

  describe('JSON proxyline', () => {
    const sh = fixtures.getServers({
      frontend: {
      },
      backends: [{
        proxyline: 'json'
      }]
    });

    it('should return empty cn cert', (cb) => {
      request(sh, '/hello', (res, body) => {
        assert.equal(sh.backends[0].requests, 1);
        assert(gotProxyline);
        cb();
      });
      let gotProxyline = false;

      sh.backends[0].server.on('proxyline', (obj) => {
        assert.equal(obj.inbound.port, sh.frontend.port);
        assert.equal(false, obj.outbound.cn);
        gotProxyline = true;
      });
    });
  });

  describe('JSON proxyline', () => {
    const sh = fixtures.getServers({
      frontend: {
      },
      backends: [{
        proxyline: 'json'
      }]
    });

    it('should return empty cn cert', (cb) => {
      request(sh, '/hello', (res, body) => {
        assert.equal(sh.backends[0].requests, 1);
        assert(gotProxyline);
        cb();
      });
      let gotProxyline = false;

      sh.backends[0].server.on('proxyline', (obj) => {
        assert.equal(obj.inbound.port, sh.frontend.port);
        assert.equal(false, obj.outbound.cn);
        gotProxyline = true;
      });
    });
  });
});

'use strict';

const assert = require('assert');
const https = require('https');
const net = require('net');
const fixtures = require('./fixtures');
const request = fixtures.request;
const caRequest = fixtures.caRequest;
const sniRequest = fixtures.sniRequest;
const spdyRequest = fixtures.spdyRequest;
const agentRequest = fixtures.agentRequest;

describe('Bud TLS Terminator/Basic', () => {
  describe('single backend', () => {
    const sh = fixtures.getServers();

    it('should support basic termination', (cb) => {
      request(sh, '/hello', (res, body) => {
        assert.equal(sh.backends[0].requests, 1);
        assert.equal(res.statusCode, 200);
        assert.equal(res.headers['x-backend-id'], 0);
        assert.equal(body, 'hello world');
        cb();
      });
    });
  });

  describe('single backend with passphrase', () => {
    const sh = fixtures.getServers({
      log: {
        level: 'debug'
      },
      frontend: {
        key: fixtures.keys.caKey,
        cert: fixtures.keys.caCert,
        passphrase: 'password'
      }
    });

    it('should support basic termination', (cb) => {
      request(sh, '/hello', (res, body) => {
        assert.equal(sh.backends[0].requests, 1);
        assert.equal(res.statusCode, 200);
        assert.equal(res.headers['x-backend-id'], 0);
        assert.equal(body, 'hello world');
        cb();
      });
    });
  });

  describe('multi-backend', () => {
    const sh = fixtures.getServers({ backends: 2 });

    it('should support round-robin balancing', (cb) => {
      request(sh, '/hello', (res, body) => {
        assert.equal(sh.backends[0].requests, 1);
        assert.equal(res.headers['x-backend-id'], 0);
        request(sh, '/hello', (res, body) => {
          assert.equal(sh.backends[1].requests, 1);
          assert.equal(res.headers['x-backend-id'], 1);
          request(sh, '/hello', (res, body) => {
            assert.equal(sh.backends[0].requests, 2);
            assert.equal(res.headers['x-backend-id'], 0);
            cb();
          });
        });
      });
    });
  });

  describe('cipher preference', () => {
    const sh = fixtures.getServers({
      frontend: {
        server_preference: true,
        ciphers: 'AES256-SHA:AES256-SHA256:AES128-SHA'
      }
    });

    it('should select server preferred cipher', (cb) => {
      const agent = new https.Agent({
        ciphers: 'AES128-SHA:AES256-SHA',
        port: sh.frontend.port
      });

      agentRequest(sh, agent, '/hello', (res, body, info) => {
        assert.equal(sh.backends[0].requests, 1);
        assert.equal(res.headers['x-backend-id'], 0);
        assert.equal(info.cipher.name, 'AES256-SHA');
        cb();
      });
    });

    it('should select server preferred cipher #2', (cb) => {
      const agent = new https.Agent({
        ciphers: 'AES128-SHA:AES256-SHA256',
        port: sh.frontend.port
      });

      agentRequest(sh, agent, '/hello', (res, body, info) => {
        assert.equal(sh.backends[0].requests, 1);
        assert.equal(res.headers['x-backend-id'], 0);
        assert.equal(info.cipher.name, 'AES256-SHA256');
        cb();
      });
    });
  });

  describe('multi-frontend', () => {
    const sh = fixtures.getServers({
      frontend: {
        interfaces: [
          { port: fixtures.FRONT_PORT },
          { port: fixtures.FRONT_PORT + 1 }
        ]
      }
    });

    it('should be reachable on both interfaces', (cb) => {
      function fire(port, cb) {
        https.get('https://127.0.0.1:' + port, (res) => {
          res.resume();
          res.once('end', cb);
        });
      }

      fire(fixtures.FRONT_PORT, () => {
        fire(fixtures.FRONT_PORT + 1, cb);
      });
    });
  });

  describe('EOF on frontend', () => {
    const sh = fixtures.getServers();

    it('should support basic termination', (cb) => {
      const socket = net.connect(sh.frontend.port);
      socket.on('close', () => {
        cb();
      });
      socket.end();
    });
  });
});

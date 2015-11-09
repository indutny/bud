var assert = require('assert');
var https = require('https');
var net = require('net');
var fixtures = require('./fixtures');
var request = fixtures.request;
var caRequest = fixtures.caRequest;
var sniRequest = fixtures.sniRequest;
var spdyRequest = fixtures.spdyRequest;
var agentRequest = fixtures.agentRequest;

describe('Bud TLS Terminator/Basic', function() {
  describe('single backend', function() {
    var sh = fixtures.getServers();

    it('should support basic termination', function(cb) {
      request(sh, '/hello', function(res, body) {
        assert.equal(sh.backends[0].requests, 1);
        assert.equal(res.statusCode, 200);
        assert.equal(res.headers['x-backend-id'], 0);
        assert.equal(body, 'hello world');
        cb();
      });
    });
  });

  describe('single backend with passphrase', function() {
    var sh = fixtures.getServers({
      log: {
        level: 'debug'
      },
      frontend: {
        key: fixtures.keys.caKey,
        cert: fixtures.keys.caCert,
        passphrase: 'password'
      }
    });

    it('should support basic termination', function(cb) {
      request(sh, '/hello', function(res, body) {
        assert.equal(sh.backends[0].requests, 1);
        assert.equal(res.statusCode, 200);
        assert.equal(res.headers['x-backend-id'], 0);
        assert.equal(body, 'hello world');
        cb();
      });
    });
  });

  describe('multi-backend', function() {
    var sh = fixtures.getServers({ backends: 2 });

    it('should support round-robin balancing', function(cb) {
      request(sh, '/hello', function(res, body) {
        assert.equal(sh.backends[0].requests, 1);
        assert.equal(res.headers['x-backend-id'], 0);
        request(sh, '/hello', function(res, body) {
          assert.equal(sh.backends[1].requests, 1);
          assert.equal(res.headers['x-backend-id'], 1);
          request(sh, '/hello', function(res, body) {
            assert.equal(sh.backends[0].requests, 2);
            assert.equal(res.headers['x-backend-id'], 0);
            cb();
          });
        });
      });
    });
  });

  describe('cipher preference', function() {
    var sh = fixtures.getServers({
      frontend: {
        server_preference: true,
        ciphers: 'AES256-SHA:AES256-SHA256:AES128-SHA'
      }
    });

    it('should select server preferred cipher', function(cb) {
      var agent = new https.Agent({
        ciphers: 'AES128-SHA:AES256-SHA',
        port: sh.frontend.port
      });

      agentRequest(sh, agent, '/hello', function(res, body, info) {
        assert.equal(sh.backends[0].requests, 1);
        assert.equal(res.headers['x-backend-id'], 0);
        assert.equal(info.cipher.name, 'AES256-SHA');
        cb();
      });
    });

    it('should select server preferred cipher #2', function(cb) {
      var agent = new https.Agent({
        ciphers: 'AES128-SHA:AES256-SHA256',
        port: sh.frontend.port
      });

      agentRequest(sh, agent, '/hello', function(res, body, info) {
        assert.equal(sh.backends[0].requests, 1);
        assert.equal(res.headers['x-backend-id'], 0);
        assert.equal(info.cipher.name, 'AES256-SHA256');
        cb();
      });
    });
  });

  describe('multi-frontend', function() {
    var sh = fixtures.getServers({
      frontend: {
        interfaces: [
          { port: fixtures.FRONT_PORT },
          { port: fixtures.FRONT_PORT + 1 }
        ]
      }
    });

    it('should be reachable on both interfaces', function(cb) {
      function fire(port, cb) {
        https.get('https://127.0.0.1:' + port, function(res) {
          res.resume();
          res.once('end', cb);
        });
      }

      fire(fixtures.FRONT_PORT, function() {
        fire(fixtures.FRONT_PORT + 1, cb);
      });
    });
  });

  describe('EOF on frontend', function() {
    var sh = fixtures.getServers();

    it('should support basic termination', function(cb) {
      var socket = net.connect(sh.frontend.port);
      socket.on('close', function() {
        cb();
      });
      socket.end();
    });
  });
});

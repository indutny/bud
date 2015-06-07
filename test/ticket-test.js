var assert = require('assert');
var tls = require('tls');
var crypto = require('crypto');
var fixtures = require('./fixtures');

describe('Bud TLS Terminator/IPC', function() {
  describe('ticket rotation', function() {
    var sh = fixtures.getServers({
      frontend: {
        ticket_rotate: 1
      }
    });

    it('should change the ticket key', function(cb) {
      var peer = tls.connect(sh.frontend.port, function() {
        var session = peer.getSession();
        var ticket = peer.getTLSTicket();
        peer.destroy();

        // It should reconnect and have the same ticket
        peer = tls.connect({
          port: sh.frontend.port,
          session: session
        }, function() {
          assert.equal(ticket.toString('hex'),
                       peer.getTLSTicket().toString('hex'));

          peer.destroy();
          setTimeout(function() {
            next(session, ticket);
          }, 1500);
        });
      });

      function next(session, ticket) {
        var peer = tls.connect({
          port: sh.frontend.port,
          session: session
        }, function() {
          assert.notEqual(ticket.toString('hex'),
                          peer.getTLSTicket().toString('hex'));

          ticket = peer.getTLSTicket();
          session = peer.getSession();
          peer.destroy();

          // It should reconnect and have the same ticket
          peer = tls.connect({
            port: sh.frontend.port,
            session: session
          }, function() {
            assert.equal(ticket.toString('hex'),
                         peer.getTLSTicket().toString('hex'));

            peer.destroy();
            cb();
          });
        });
      }
    });
  });
});

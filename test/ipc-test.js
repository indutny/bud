var assert = require('assert');
var tls = require('tls');
var crypto = require('crypto');
var fixtures = require('./fixtures');

describe('Bud TLS Terminator/IPC', function() {
  describe('set ticket', function() {
    var sh = fixtures.getServers({
      master_ipc: true
    });

    function changeKey(index, cb) {
      var head = new Buffer(9);

      // type = setTicket
      head.writeUInt8(0x3, 0);

      head.writeUInt32BE(52, 1);
      head.writeUInt32BE(index, 5);

      var msg = Buffer.concat([
        head,
        crypto.randomBytes(48)
      ]);

      sh.frontend.server.proc.stdin.write(msg, cb);
    }

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
          next(session, ticket);
        });
      });

      function next(session, ticket) {
        changeKey(0, function() {
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
        });
      }
    });
  });
});

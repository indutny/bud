'use strict';

const assert = require('assert');
const tls = require('tls');
const crypto = require('crypto');
const fixtures = require('./fixtures');

describe('Bud TLS Terminator/IPC', () => {
  describe('set ticket', () => {
    const sh = fixtures.getServers({
      master_ipc: true
    });

    function changeKey(index, cb) {
      const head = new Buffer(9);

      // type = setTicket
      head.writeUInt8(0x3, 0);

      head.writeUInt32BE(52, 1);
      head.writeUInt32BE(index, 5);

      const msg = Buffer.concat([
        head,
        crypto.randomBytes(48)
      ]);

      sh.frontend.server.proc.stdin.write(msg, cb);
    }

    it('should change the ticket key', (cb) => {
      let peer = tls.connect(sh.frontend.port, () => {
        const session = peer.getSession();
        const ticket = peer.getTLSTicket();
        peer.destroy();

        // It should reconnect and have the same ticket
        peer = tls.connect({
          port: sh.frontend.port,
          session: session
        }, () => {
          assert.equal(ticket.toString('hex'),
                       peer.getTLSTicket().toString('hex'));

          peer.destroy();
          next(session, ticket);
        });
      });

      function next(session, ticket) {
        changeKey(0, () => {
          let peer = tls.connect({
            port: sh.frontend.port,
            session: session
          }, () => {
            assert.notEqual(ticket.toString('hex'),
                            peer.getTLSTicket().toString('hex'));

            ticket = peer.getTLSTicket();
            session = peer.getSession();
            peer.destroy();

            // It should reconnect and have the same ticket
            peer = tls.connect({
              port: sh.frontend.port,
              session: session
            }, () => {
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

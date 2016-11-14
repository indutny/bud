'use strict';

const assert = require('assert');
const tls = require('tls');
const crypto = require('crypto');
const fixtures = require('./fixtures');

describe('Bud TLS Terminator/IPC', () => {
  describe('ticket rotation', () => {
    const sh = fixtures.getServers({
      frontend: {
        ticket_rotate: 1
      }
    });

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
          setTimeout(() => next(session, ticket), 1500);
        });
      });

      function next(session, ticket) {
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
      }
    });
  });
});

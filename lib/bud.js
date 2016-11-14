'use strict';

const assert = require('assert');
const path = require('path');
const spawn = require('child_process').spawn;
const util = require('util');
const EventEmitter = require('events').EventEmitter;

const binary = path.resolve(__dirname, '..', 'bin', 'bud');

function Server(options) {
  EventEmitter.call(this);

  this.options = options ? util._extend({}, options) : {};
  this.proc = null;
}
util.inherits(Server, EventEmitter);
module.exports = Server;

Server.createServer = function createServer(options) {
  return new Server(options);
};

Server.prototype.listen = function listen(port, host, cb) {
  assert(!this.proc, 'Server is already listening');

  if (!cb && typeof host === 'function') {
    cb = host;
    host = null;
  }
  if (!cb && typeof port === 'function') {
    cb = port;
    port = 0;
  }
  if (!port)
    port = 1443;
  if (!cb)
    cb = () => {};

  if (host)
    this.options.host = host;
  if (!this.options.frontend)
    this.options.frontend = {};
  this.options.frontend.port = port;

  if (cb)
    this.once('listening', cb);

  this.proc = spawn(binary, [ '-i', JSON.stringify(this.options) ], {
    stdio: [ 'pipe', 1, 'pipe' ]
  });

  // Wait for "bud listening on [%s]:%d"
  let chunks = '';
  let once = false;
  this.proc.stderr.on('readable', () => {
    const chunk = this.proc.stderr.read();
    if (!chunk)
      return;

    if (once)
      return;
    chunks += chunk;
    assert(chunks.length < 16 * 1024);

    const match = chunks.match(/listening on \[([^\]]*)\]:(\d+)/);
    if (!match)
      return;

    once = true;
    this.emit('listening');
  });

  this.proc.once('close', (code) => {
    this.emit('error', new Error('Process died: ' + code));
  });
};

Server.prototype.close = function close(cb) {
  this.proc.kill();
  this.proc.removeAllListeners('close');
  this.proc.once('close', () => {
    // Allow reuse
    this.proc = null;

    // Notify event listeners and invoke callback
    this.emit('close');
  });

  if (cb)
    this.once('close', cb);
};

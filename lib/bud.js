var assert = require('assert');
var path = require('path');
var spawn = require('child_process').spawn;
var util = require('util');
var EventEmitter = require('events').EventEmitter;

var binary = path.resolve(__dirname, '..', 'npm', 'bud');

function Server(options) {
  EventEmitter.call(this);

  this.options = util._extend({}, options || {});
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
    cb = function() {};

  if (host)
    this.options.host = host;
  if (!this.options.frontend)
    this.options.frontend = {};
  this.options.frontend.port = port;

  if (cb)
    this.once('listening', cb);

  this.proc = spawn(binary, [ '-i', JSON.stringify(this.options) ]);

  // Wait for "bud listening on [%s]:%d"
  var self = this;
  var chunks = '';
  this.proc.stderr.on('readable', function onReadable() {
    var chunk = this.read();
    if (!chunk)
      return;

    chunks += chunk;
    assert(chunks.length < 16 * 1024);

    var match = chunks.match(/listening on \[([^\]]*)\]:(\d+)/);
    if (!match)
      return;

    self.emit('listening');
  });

  this.proc.once('close', function(code) {
    self.emit('error', new Error('Process died: ' + code));
  });
};

Server.prototype.close = function close(cb) {
  var self = this;

  this.proc.kill();
  this.proc.removeAllListeners('close');
  this.proc.once('close', function() {
    // Allow reuse
    self.proc = null;

    // Notify event listeners and invoke callback
    self.emit('close');
  });

  if (cb)
    this.once('close', cb);
};

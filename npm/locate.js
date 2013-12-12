// Locate result of the build

var fs = require('fs');
var path = require('path');

var paths = [
  ['build'],
  ['build', 'Release'],
  ['build', 'Debug'],
  ['out', 'Release'],
  ['out', 'Debug'],
  ['build', 'default']
];

var exenames = [ 'bud', 'bud.exe' ];

var root = path.resolve(__dirname, '..');

for (var i = 0; i < paths.length; i++) {
  for (var j = 0; j < exenames.length; j++) {
    var exename = exenames[j];
    var filename = path.resolve.apply(path, [root].concat(paths[i], exename));

    try {
      fs.statSync(filename);
    } catch(e) {
      continue;
    }

    try {
      fs.symlinkSync(filename, path.resolve(root, exename));
    } catch (e) {
      // Ignore errors
    }
    process.exit(0);
  }
}

console.error('Build result not found');
process.exit(1);

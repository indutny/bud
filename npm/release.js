#!/usr/bin/env node
var fs = require('fs');
var spawn = require('child_process').spawn;
var semver = require('semver');

// Update version and save package.json
var package = require(__dirname + '/../package.json');
package.version = semver.inc(package.version, process.argv[2]);
fs.writeFileSync(__dirname + '/../package.json',
                 JSON.stringify(package, null, 2) + '\n');

// Update src/version.h
var v = semver.parse(package.version);
var header = fs.readFileSync(__dirname + '/../src/version.h').toString();

header = header.replace(/(BUD_VERSION_MAJOR )\d+/, function(all, key) {
  return key + v.major;
});
header = header.replace(/(BUD_VERSION_MINOR )\d+/, function(all, key) {
  return key + v.minor;
});
header = header.replace(/(BUD_VERSION_PATCH )\d+/, function(all, key) {
  return key + v.patch;
});

fs.writeFileSync(__dirname + '/../src/version.h', header);

// git tag
var tag = 'v' + package.version;
var commitProc = spawn('git', [ 'commit', '-asS', '-m', tag ], {
  stdio: 'inherit'
});

commitProc.once('exit', function(code) {
  if (code !== 0)
    return;
  var tagProc = spawn('git', [ 'tag', '-s', tag, '-m', tag ], {
    stdio: 'inherit'
  });
});

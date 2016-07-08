#!/usr/bin/env node
'use strict';

const fs = require('fs');
const path = require('path');
const spawn = require('child_process').spawn;
const semver = require('semver');
const gitSecureTag = require('git-secure-tag');

const root = path.join(__dirname, '..');

// Update version and save package.json
const packageFile = path.join(root, 'package.json');
const pkg = require(packageFile);
pkg.version = semver.inc(pkg.version, process.argv[2]);
fs.writeFileSync(packageFile,
                 JSON.stringify(pkg, null, 2) + '\n');

// Update src/version.h
const v = semver.parse(pkg.version);
const versionFile = path.join(root, 'src', 'version.h');
let header = fs.readFileSync(versionFile).toString();

header = header.replace(/(BUD_VERSION_MAJOR )\d+/, function(all, key) {
  return key + v.major;
});
header = header.replace(/(BUD_VERSION_MINOR )\d+/, function(all, key) {
  return key + v.minor;
});
header = header.replace(/(BUD_VERSION_PATCH )\d+/, function(all, key) {
  return key + v.patch;
});

fs.writeFileSync(versionFile, header);

// git tag
const tag = 'v' + pkg.version;
const commitProc = spawn('git', [ 'commit', '-asS', '-m', tag ], {
  stdio: 'inherit'
});

commitProc.once('exit', function(code) {
  if (code !== 0)
    return;
  const api = new gitSecureTag.API(root);
  api.sign(tag, 'HEAD');
});

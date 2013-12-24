# Bud vs Stud benchmarks

I used two [SmartOS][0] in a [Joyent Cloud][1]: one 16 core (server) and one
4 core (client). Both servers were initialized with a [bootstrap repo][2].

## Boostrap instructions

On both machines:

```bash
pkgin -y update && pkgin -y install scmgit
git clone git@github.com:indutny/bud-benchmark-comparison.git
cd bud-benchmark-comparison
```

On server:

```bash
./init-server.sh
```

On client:

```bash
./init-client.sh <server-ip>
node process.js > normal.csv
./init-client.sh <server-ip> big
node process.js > big.csv
```

`normal.csv` - will contain [CSV][3] data for a "hello world" response endpoint,
`big.csv` - will contain outputs for a 128kb "AAA..." responses.

## Charts

Normal response:

![https://raw.github.com/indutny/bud/master/benchmarks/normal-rps.png](Normal RPS)
![https://raw.github.com/indutny/bud/master/benchmarks/normal-resp.png](Normal Response)

Big response:

![https://raw.github.com/indutny/bud/master/benchmarks/big2-rps.png](Big RPS)
![https://raw.github.com/indutny/bud/master/benchmarks/big2-resp.png](Big Response)

[0]: http://smartos.org/
[1]: http://www.joyent.com/
[2]: https://github.com/indutny/bud-benchmark-comparison
[3]: http://en.wikipedia.org/wiki/Comma-separated_values

# Fantasma Cero [WIP]

A web firewall (WAF) that both scares away and lures those pesky LLM/AI scraper bots. It hits an incoming HTTP request with a quick check — "Are you human, or just another bloody AI scraper in a trench coat?"— before letting it in.

![challenge page](https://fantasma0.turbamentum.one/assets/img1a.png)


## Usage

Being customizable, *Fantasma Cero*  supports and employs some of the features:
* Proof-of-Work (PoW) basic challenge
* GPU-resisent PoW algorithm - `argon2`
* Trap endpoint detection
* Wrong and decoy content which poisons AI scrapers

Only verified visitors are allowed through to the configured backend.

### Running

1. Download and install a release
```
# set the proper release version
VERSION="v0.1.0"

curl -L -O https://github.com/cocky-punch/fantasma_cero/releases/download/$VERSION/fantasma_cero-$VERSION-x86_64-unknown-linux-gnu.tar.gz

tar -xzf fantasma_cero-$VERSION-x86_64-unknown-linux-gnu.tar.gz
cd fantasma_cero-$VERSION-x86_64-unknown-linux-gnu
```

2. Configure your backend and secrets in `config.toml`
```
cp config.example.toml config.toml
nano config.toml
```

3. Also check the example webserver configs in `./examples` for:
- nginx
- caddy

Edit the one you need accordingly: port, host, etc; copy it into or merge with your Nginx or Caddy config.

4. Run it:

   ```bash
   ./fantasma_cero
   ```

By default, the admin dashboard is at: http(s)://{host}:8081/fantasma0/admin



### TODO
- [x] option "JS must be enabled/supported"
- [ ] poison AI-LLM scrapers with fake data
- [ ] different PoW difficulty per route
- [x] basic admin backend and metrics
- [ ] attribution of AI-LLM scrapers
- [ ] ASN-based decisions and bans
- [x] skippable URL paths
- [ ] error reports, feedback

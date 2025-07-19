# Fantasma Cero

A web firewall that both scares away and lures those pesky LLM/AI scraper bots. It hits an incoming HTTP request with a quick check — "Are you human, or just another bloody AI scraper in a trench coat?"— before letting it in.


## Usage

*Fantasma Cero* being a customizible tool, acts as a lightweight web firewall and reverse proxy. It supports and employs:

* Proof-of-Work (PoW) challenge
* HMAC tokens
* JWT tokens
* Trap endpoint detection
* Wrong and decoy content

Only verified visitors are allowed through to the configured backend.

### Running

1. Configure your backend and secrets in `config.toml`.
2. Start the server:

   ```bash
   cargo run --release
   ```
3. Point your domain or client traffic to the proxy server.

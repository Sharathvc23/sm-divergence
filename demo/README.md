# The demo site

A live demo of sm-divergence: John's personal agent, Pim, is about to book a trip with Travel26 and
asks every place Travel26's booking agent is listed before it sends anything.

Each run builds four fictional sources (`world.py`): a zone served over DNS-over-HTTPS through two
resolvers, a registry, a transparency log that issues signed receipts and status tokens, and a
catalog document. A story (`stories.py`) changes what one source says, runs the library's own
sweep against them over HTTP, checks the result, and seals it in a signed Corroboration Record that
the page verifies in the browser (`static/verify.js`). Nothing in the library is patched; every
name ends in `.example`.

## Run it

    uv sync --extra site
    uv run python -m demo.server        # http://localhost:8080

or `docker build -t sm-divergence-demo . && docker run -p 8080:8080 -v quilt-data:/data sm-divergence-demo`.

## Configuration

| Variable | Meaning |
| --- | --- |
| `PORT` | Port to listen on (default 8080). |
| `QUILT_DATA` | Directory for the site's signing key and the latest run of each story. `/data` in the image: mount a volume there, or every deploy signs with a new key. |
| `ADMIN_TOKEN` | Optional. A bearer token that lifts the run limits (three at a time, five per visitor every ten minutes). |
| `PUBLIC_URL` | Optional. The address visitors reach the site at, used in the links to a run's sources. Derived from the request when unset. |
| `LOOKUP_DOH` | Optional. `name=https://…/dns-query,name=https://…/dns-query`: the DNS-over-HTTPS resolvers the "try a real name" box asks. Unset, the box is hidden. |

The lookup places the visitor's name in a DNS question to those resolvers and nowhere else; the
site never fetches an address a visitor supplies.

## Routes

`/` the page · `/console` run a story live · `/health` · `/config` · `/key` the site's `did:key` ·
`POST /api/runs` · `GET /api/runs` · `/api/latest` · `/api/runs/{id}` · `/api/runs/{id}/events` (SSE) ·
`/runs/{id}/…` that run's sources, while the run is among the most recent · `POST /api/lookup`.

## Tests

`tests/test_site.py` runs every story in-process and exercises the HTTP surface.

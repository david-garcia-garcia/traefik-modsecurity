# Replace ad-hoc reclaim table with upstream traefik-middleware-utilities import

Replace the ad-hoc reclaim table in this project with the upstream https://github.com/david-garcia-garcia/traefik-middleware-utilities managed as an import.

This repo currently keeps a local reclaim implementation (pkg/reclaim) used by the Traefik ModSecurity plugin to keep one plugin core across Traefik reloads. Stop using that ad-hoc in-tree table. Add the upstream module as a Go import and use its reclaim package instead. The upstream is a Yaegi-safe toolbox (reclaim, simpleredis, windowcounter, tokenbucket, backendbackoff, iplookup). This ticket is the reclaim replacement via import, not a rewrite of those other packages into this repo.

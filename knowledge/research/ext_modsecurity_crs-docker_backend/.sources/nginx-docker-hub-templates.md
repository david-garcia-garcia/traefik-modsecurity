---
url: https://hub.docker.com/_/nginx
title: Docker Hub official nginx — environment variables in configuration
fetched: 2026-09-03
authority: official
---

Since 1.19, the image runs envsubst on templates before nginx starts. Default: read `/etc/nginx/templates/*.template`, write to `/etc/nginx/conf.d` (suffix stripped).

`NGINX_ENVSUBST_TEMPLATE_DIR` default `/etc/nginx/templates`. `NGINX_ENVSUBST_OUTPUT_DIR` default `/etc/nginx/conf.d`. Output filename is the template name without suffix; subdirectory layout is preserved relative to the template dir when OUTPUT_DIR is changed.

Script on the image: `/docker-entrypoint.d/20-envsubst-on-templates.sh` (named by CRS README).

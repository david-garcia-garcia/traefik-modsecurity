# Extract: CRS docker request body limit env

Source: https://github.com/coreruleset/modsecurity-crs-docker/blob/master/README.md
Retrieved: 2026-09-02

| Name | Description |
| -------- | ------------------------------------------------------------------- |
| MODSEC_REQ_BODY_LIMIT_ACTION | A string value for the action when `SecRequestBodyLimit` is reached (Default: `Reject`). Accepted values: `Reject`, `ProcessPartial`. |
| MODSEC_REQ_BODY_LIMIT | An integer value indicating the maximum request body size accepted for buffering (Default: `13107200`). |
| MODSEC_REQ_BODY_NOFILES_LIMIT | An integer indicating the maximum request body size ModSecurity will accept for buffering (Default: `131072`). |

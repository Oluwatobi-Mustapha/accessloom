# sqlcdb

This directory is reserved for sqlc-generated query code.

Generation command:

```bash
cd sqlc
sqlc generate
```

Current Postgres store code is manually written and query-compatible with files in `sqlc/queries`.
The next iteration will switch runtime calls to generated methods from this package.

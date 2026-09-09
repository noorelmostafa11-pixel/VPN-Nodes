# Data files

`GeoLite2-Country.mmdb` is the local offline country database used by `scripts/country_resolver.py`. It is refreshed by `.github/workflows/update_geolite2.yml` on the 1st and 15th of each month and can also be refreshed manually.

`GEOLITE2_SOURCE.md` records the current distribution source and redistribution notice.

`catalog_signing_public_key.pem` is the public verification key for the generated catalog manifest. The private signing key is never stored in this repository.

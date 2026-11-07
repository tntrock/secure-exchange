# Task 2 report
- check-version.sh: ok -> rc0; `v1.0.0` -> rc0; `v9.9.9` -> rc1 (tag mismatch msg); compose tag broken to 1.0.1 -> rc1 (prints found lines); restored -> rc0.
- `bash scripts/e2e.sh` (overlay order yml, build, e2e): 15 passed, EXIT=0.
- `docker compose -f docker-compose.yml config`: 0 `build:`; with `-f docker-compose.build.yml`: build for app (target app) and worker (target worker), VERSION: dev.
- check-image.sh on both locally built ghcr images: ok, rc0. On throwaway image FROM app + `USER root` + added .env: "sx-bad: user is 'root', expected 65532:65532", rc1; image removed.
- `SMOKE_PREBUILT=1 bash scripts/smoke.sh` with compose temporarily tagged 9.9.9: prints "image ...:9.9.9 is not present locally; pull or build it first", rc1; compose restored (check-version ok). Full smoke not run.
- ci.yml docker job: check-version, two target builds (sxapp, sxworker), check-image.

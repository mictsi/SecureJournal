# Release Notes

## v0.4.0 - 2026-02-27

### Highlights

- Added GitHub Actions tag build workflow (`push` on `v*`) with restore/build/test/publish and artifact upload.
- Added workflow status badge to `README.md`.
- Added Docker packaging (`Dockerfile`, `docker-compose.yml`, `.dockerignore`) for local and cloud-hosted container runs.
- Added rootless container runtime (non-root user `10001:10001`) in both Docker image and compose setup.
- Added environment-variable-first configuration support for Docker and Azure App Service, including:
  - standard hierarchical .NET keys (`Section__Subsection__Key`)
  - Azure connection-string prefixes (`SQLCONNSTR_*`, `POSTGRESQLCONNSTR_*`, `CUSTOMCONNSTR_*`, etc.)
  - optional shorthand env vars for common security/connection values
- Added script to generate env files from appsettings:
  - `scripts/generate-env-from-appsettings.ps1`

### Technical Notes

- Persistence options now support direct connection string overrides:
  - `Persistence:AppConnectionString`
  - `Persistence:IdentityConnectionString`
- Updated template appsettings files to include the new persistence override keys.
- Updated deployment and build documentation for CI, Docker, and environment-variable workflows.

## v0.3.0 - 2026-02-27

### Highlights

- Improved `My Projects` journal readability with a column-header row and single-line, flex-based entries.
- Added date sorting (`Newest first` / `Oldest first`) in `My Projects`.
- Added dedicated journal entry details page (`/projects/entry/{recordId}`) with Back navigation.
- Added `Add Journal Entry` action in `My Projects`.
- After creating an entry in `/journal`, users now return to `/projects` with the created project preselected.
- Removed checksum display from `My Projects` entry rows.
- Updated `Audit Search` results with a dedicated `Integrity` column for checksum + validation controls.
- Added alternating row colors (zebra striping) for table/list readability across pages.

### Technical Notes

- Documentation and specification were updated to match current behavior.
- Release build artifact target: `securejournal-web-v0.3.0.zip` (published web output).

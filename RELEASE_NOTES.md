# Release Notes

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

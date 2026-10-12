# ZIP inventory coverage description

Issue: https://github.com/morluto/rea/issues/2330

## Problem and requirements

The canonical ZIP limitation incorrectly locates APK signing blocks after the
central directory. Explain that inventory reports central-directory entries,
not non-entry bytes, regardless of their position. Keep whole-file provenance
and existing artifact comparison semantics.

## Acceptance

- The emitted limitation covers signing blocks before the directory and comments.
- A boundary test inventories two archives with identical entries and different
  comments: equal child hashes, different whole-file hashes, no comment occurrence.
- Existing comparison tests and relevant static checks pass.

## Out of scope

Parsing or verifying signatures, exposing comments as entries, adding providers,
executing targets or modifying caller files.

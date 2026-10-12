# Implementation plan

Correct the string at its owner, src/domain/zipPackageFormat.ts. Retain the
exported ZIP_NON_ENTRY_TAIL_LIMITATION name to avoid an unnecessary API change.
Inventory and comparison already import the same constant; no downstream repair
or alternate representation is needed.

Add a real ZIP inventory regression in the existing archive boundary test file.
Generate archives locally with zip.js, varying only their comment. Assert the
reported coverage limitation, equal entry hashes and distinct root hashes.
Run focused tests, the comparison domain suite and check:fast.

Primary format reference:
https://source.android.com/docs/security/features/apksigning/v2#apk-signing-block

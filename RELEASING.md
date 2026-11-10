# Releasing Aegis

The rules that keep every published release green and exactly
as described.

1. **Tag only a green commit.** Push the release commit to
   main, wait for the aegis-ci run for that exact commit to
   complete successfully on all three OSes, and only then
   create the tag. The release workflow enforces this: its
   verify job refuses a tagged commit that is not on main or
   has no successful CI run for that exact SHA.
2. **A published tag is never moved.** If a published release
   turns out to be wrong, the fix ships as a new patch version
   (v5.0.1 after v5.0.0), never as a rewritten tag. Moving a
   tag silently changes what every existing download, mirror,
   and attestation points at. An unpublished tag whose build
   failed before any release existed may be deleted and
   recreated at the fixed commit.
3. **Assets are an explicit set, never a glob.** A release
   carries exactly two assets: the reproducible source zip
   and its SBOM, both named from the tag. The workflow builds
   into a fresh dist directory, asserts the set before
   publishing, and re-checks the published set from the
   server side afterwards. `dist/` is never tracked in git;
   CI fails if it ever is.
4. **Filenames have one source of truth.** The asset name is
   derived from the tag in the workflow, and the build
   script's own default name is never used by the release
   workflow.
5. **Tests probe capabilities, not platform names.** A test
   that needs an OS facility (extended attributes, an
   executable format, a path convention) probes whether it
   actually works on the runner and skips with the probe
   result as the reason. Skipping on `sys.platform` alone is
   how the v4.0.0 and v5.0.0 tag runs went red on Windows and
   macOS while Linux stayed green.

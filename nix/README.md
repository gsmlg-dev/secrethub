# Asset build inputs

The Core package builds frontend assets with `mix npm.ci` and
`mix duskmoon_bundler.build secrethub_web --tailwind`. Asset compilation does not
start SecretHub or load production runtime configuration.

GNU asset builds require Ubuntu 26.04 and glibc 2.43 or newer. The published Vize
10.1.2 GNU compiler requires `GLIBC_2.43`; the current local Nix environment
provides glibc 2.42 and cannot load it. Production asset generation is therefore
`BLOCKED_ENV` on that environment, even when Mix compilation succeeds. Prefetching
the native archive preserves its ABI requirements.

This is the [upstream maintainer's supported environment contract](https://github.com/duskmoon-dev/duskmoon-bundler/issues/9#issuecomment-6396025627).
Issue #9 is closed as not planned; support for older glibc versions is outside
that contract. Core GNU release builds use the available GitHub-hosted
[`ubuntu-26.04` and `ubuntu-26.04-arm` images](https://github.com/actions/runner-images#available-images).
The Alpine Docker builders use separate musl native artifacts and need their own
asset-build qualification.

`npm-cache.nix` fetches packages using the integrity values in the root
`package-lock.json`. `tailwind-runtime.json` pins the bundler's separate compiler
runtime to Tailwind 4.3.5 and the typography dependency graph.
`prepare-tailwind-runtime.exs` links that runtime from the cache without registry
resolution. Update the runtime graph when the bundler's Tailwind requirements
change.

`native-artifacts.json` records archive URLs and SHA-256 checksums from the
published native dependency checksum files for every supported flake system.
Update these records when DuskmoonBundler or MDEx native versions change. Both
RustlerPrecompiled, ZiglerPrecompiled and ElixirMake receive the resulting
offline cache, including LazyHTML's precompiled parser.

After changing Mix dependencies, regenerate the `fetchMixDeps` hash and build the
Core package to verify the asset cache and native artifacts together. A syntax
check or dependency hash alone does not qualify the complete Nix package.

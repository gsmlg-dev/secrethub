# Asset build inputs

The Core package builds frontend assets with `mix npm.ci` and
`mix duskmoon_bundler.build secrethub_web --tailwind`. Asset compilation does not
start SecretHub or load production runtime configuration.

The published Vize 10.1.11 GNU compiler requires glibc 2.43 or newer.
Run `devenv update` before building assets locally. On Linux, the devenv
shell uses Erlang/Elixir from rolling Nixpkgs, where the compiler can load
against glibc 2.44. PostgreSQL continues to use the stable Nixpkgs input.

The release flake's Nixpkgs 25.11 input provides glibc 2.40. Core GNU
release builds use GitHub-hosted
[`ubuntu-26.04` and `ubuntu-26.04-arm` images](https://github.com/actions/runner-images#available-images).
The [upstream maintainer documents the GNU compiler baseline](https://github.com/duskmoon-dev/duskmoon-bundler/issues/9#issuecomment-6396025627).
The Alpine Docker builders use separate musl native artifacts.

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

# Seed the bundler's isolated runtime from pinned inputs without loading app config.
[lockfile] = System.argv()
packages = %{"tailwindcss" => "^4.3.0", "@tailwindcss/typography" => "^0.5.20"}

signature =
  packages
  |> Enum.sort()
  |> :erlang.term_to_binary()
  |> :erlang.md5()
  |> Base.encode16(case: :lower)

install_dir = Path.join(System.fetch_env!("DUSKMOON_BUNDLER_JS_RUNTIME_DIR"), signature)
File.mkdir_p!(install_dir)

{:ok, resolved} = NPM.Lockfile.read(lockfile)
:ok = NPM.Install.Linker.link(resolved, Path.join(install_dir, "node_modules"))
File.cp!(lockfile, Path.join(install_dir, "npm.lock"))

File.write!(
  Path.join(install_dir, "duskmoon-bundler-runtime.json"),
  Jason.encode!(%{signature: signature, packages: packages})
)

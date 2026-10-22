# Run after compilation: MIX_ENV=test mix run --no-start scripts/test-pki-acme-protocol.exs
# Keeps pure protocol fixtures independent of database/runtime test support.
Application.ensure_all_started(:jose)
Application.load(:castore)
ExUnit.start()

for file <- ~w(protocol_test.exs certificate_validation_test.exs pebble_test.exs) do
  Code.require_file(Path.join("apps/secrethub_core/test/secrethub_core/pki/acme", file))
end

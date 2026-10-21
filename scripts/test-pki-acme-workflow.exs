# Invoked by test-pki-acme-pebble.sh with SECRETHUB_PEBBLE_RUN_SCRIPT set.
Mix.Task.run("test", [
  "apps/secrethub_core/test/secrethub_core/pki/acme/workflow_test.exs",
  "--only",
  "pebble"
])

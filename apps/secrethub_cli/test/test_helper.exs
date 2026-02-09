# Start Mox server for mock support
Application.ensure_all_started(:mox)

# Define Mox mocks for HTTP client
# TODO: Implement HTTPClientBehaviour and enable mocking
# Mox.defmock(SecretHub.CLI.HTTPClientMock, for: SecretHub.CLI.HTTPClientBehaviour)

# Start ExUnit
ExUnit.start()

defmodule SecretHub.Core.PKI.X509DependencyTest do
  use ExUnit.Case, async: true

  test "uses the SecretHub-owned local X509 application" do
    x509_path = Mix.Project.deps_paths()[:x509]

    assert x509_path == Path.expand("../../../../x509", __DIR__)
  end
end

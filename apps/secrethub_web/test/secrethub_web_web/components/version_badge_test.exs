defmodule SecretHub.Web.VersionBadgeTest do
  use ExUnit.Case, async: true

  import Phoenix.LiveViewTest

  alias SecretHub.Web.Layouts

  test "appbar shows the running version beside the brand" do
    html = render_component(&Layouts.app/1, flash: %{}, inner_content: "Content")
    document = LazyHTML.from_fragment(html)
    version = to_string(Application.spec(:secrethub_web, :vsn))

    assert document |> LazyHTML.query(".appbar #app-version") |> LazyHTML.text() =~ "v#{version}"
  end

  test "development versions have a dev suffix and a keyboard-accessible details tooltip" do
    html = render_component(&Layouts.version_badge/1, info: info(:dev))
    document = LazyHTML.from_fragment(html)
    trigger = LazyHTML.query(document, "#app-version")
    tooltip = LazyHTML.query(document, "[role=tooltip]")

    assert trigger |> LazyHTML.text() |> String.trim() == "v2.3.4-rc1-dev"
    assert LazyHTML.attribute(trigger, "aria-describedby") == ["app-version-tooltip"]
    assert LazyHTML.attribute(trigger, "type") == ["button"]

    assert LazyHTML.text(tooltip) =~ "Git ref: main"
    assert LazyHTML.text(tooltip) =~ "Git SHA: 1234567890abcdef"
    assert LazyHTML.text(tooltip) =~ "Built at: 2026-10-10T12:00:00Z"
  end

  test "production and test versions keep the release version without a dev suffix" do
    for environment <- [:prod, :test] do
      html = render_component(&Layouts.version_badge/1, info: info(environment))

      assert html
             |> LazyHTML.from_fragment()
             |> LazyHTML.query("#app-version")
             |> LazyHTML.text()
             |> String.trim() == "v2.3.4-rc1"
    end
  end

  test "source timestamps and missing git metadata remain explicit" do
    info = %{
      info(:prod)
      | git_ref: nil,
        git_sha: nil,
        built_at: nil,
        source_date: "2026-10-09T12:00:00Z"
    }

    html = render_component(&Layouts.version_badge/1, info: info)

    assert html =~ "Git ref: Unavailable"
    assert html =~ "Git SHA: Unavailable"
    assert html =~ "Source time: 2026-10-09T12:00:00Z"
    refute html =~ "Built at:"
  end

  defp info(environment) do
    %{
      version: "2.3.4-rc1",
      environment: environment,
      git_ref: "main",
      git_sha: "1234567890abcdef",
      built_at: "2026-10-10T12:00:00Z",
      source_date: nil
    }
  end
end

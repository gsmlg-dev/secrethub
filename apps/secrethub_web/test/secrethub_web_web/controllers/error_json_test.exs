defmodule SecretHub.Web.ErrorJSONTest do
  use SecretHub.Web.ConnCase, async: true

  test "renders 404" do
    assert SecretHub.Web.ErrorJSON.render("404.json", %{}) == %{errors: %{detail: "Not Found"}}
  end

  test "renders 500" do
    assert SecretHub.Web.ErrorJSON.render("500.json", %{}) ==
             %{errors: %{detail: "Internal Server Error"}}
  end
end

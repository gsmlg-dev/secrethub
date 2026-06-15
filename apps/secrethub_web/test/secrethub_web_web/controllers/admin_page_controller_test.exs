defmodule SecretHub.Web.AdminPageControllerTest do
  use SecretHub.Web.ConnCase, async: false

  setup do
    previous_dev_mode = Application.get_env(:secrethub_web, :dev_mode)

    Application.put_env(:secrethub_web, :dev_mode, true)

    on_exit(fn ->
      Application.put_env(:secrethub_web, :dev_mode, previous_dev_mode)
    end)

    :ok
  end

  test "development password input uses input styling", %{conn: conn} do
    html =
      conn
      |> get(~p"/admin/auth/login")
      |> html_response(200)

    assert html =~
             ~r/<input(?=[^>]*id="dev_password")(?=[^>]*type="password")(?=[^>]*class="[^"]*\binput\b)[^>]*>/
  end
end

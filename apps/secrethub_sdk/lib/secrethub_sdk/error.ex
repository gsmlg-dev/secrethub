defmodule SecretHub.SDK.Error do
  @moduledoc """
  A failed SDK call.

  `code` distinguishes the cases a caller usually handles differently:

    * `:agent_unavailable` - the Agent socket could not be reached or the
      connection failed before a response arrived. Nothing is known about Core.
    * `:unconfirmed` - a write or delete was sent but its outcome is unknown
      (for example a lost reply). It may have been applied; retry or verify.
    * `:forbidden` - Core denied the operation for this Agent and path. Reads
      also report a missing secret as `:forbidden`, so a reader cannot probe
      for paths it is not allowed to see.
    * `:conflict` - `expected_version` did not match the current version.
    * `:invalid_request` - the path or data was rejected by the contract.
    * `:sealed`, `:unavailable`, `:audit_unavailable`, `:busy`,
      `:incompatible_version`, `:enrollment_in_progress`, `:unauthorized`,
      `:read_only` - SecretHub-side conditions; `agent_code` holds the raw code.
    * `:unknown` - an Agent code this SDK version does not recognise.
  """

  defexception [:code, :agent_code, :message]

  @type t :: %__MODULE__{code: atom(), agent_code: String.t() | nil, message: String.t()}

  @codes %{
    "FORBIDDEN" => :forbidden,
    "UNAUTHORIZED" => :unauthorized,
    "NOT_FOUND" => :not_found,
    "CONFLICT" => :conflict,
    "INVALID_REQUEST" => :invalid_request,
    "READ_ONLY" => :read_only,
    "UNCONFIRMED" => :unconfirmed,
    "INCOMPATIBLE_VERSION" => :incompatible_version,
    "VAULT_SEALED" => :sealed,
    "UNAVAILABLE" => :unavailable,
    "AUDIT_UNAVAILABLE" => :audit_unavailable,
    "BUSY" => :busy,
    "ENROLLMENT_IN_PROGRESS" => :enrollment_in_progress,
    "AGENT_SCOPE_REQUIRED" => :forbidden,
    "PROOF_REQUIRED" => :forbidden
  }

  @doc false
  def from_agent(code) when is_binary(code) do
    mapped = Map.get(@codes, code, :unknown)
    %__MODULE__{code: mapped, agent_code: code, message: "SecretHub Agent returned #{code}"}
  end

  @doc false
  def new(code, message), do: %__MODULE__{code: code, message: message}
end

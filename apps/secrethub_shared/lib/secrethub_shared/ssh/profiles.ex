defmodule SecretHub.Shared.SSH.Profiles do
  @moduledoc "Strict OpenSSH profiles for explicitly managed clients and destination accounts."

  @lookup "/run/secrethub-ssh/lookup.sock"
  @signing "/run/secrethub-ssh-signing/agent.sock"

  def client(opts) do
    with {:ok, base, lookup} <- paths(opts),
         hosts when is_list(hosts) and hosts != [] and length(hosts) <= 128 <-
           Keyword.get(opts, :hosts),
         true <- Enum.all?(hosts, &safe_host?/1),
         signing <- Keyword.get(opts, :signing_socket, @signing),
         true <- safe_path?(signing) do
      {:ok,
       """
       Host #{Enum.uniq(hosts) |> Enum.join(" ")}
         IdentityAgent #{signing}
         KnownHostsCommand #{base}/bin/secrethub_agent fetch-ssh-host-keys --socket #{lookup} %I %H %p
         StrictHostKeyChecking yes
         VerifyHostKeyDNS no
         UserKnownHostsFile /dev/null
         GlobalKnownHostsFile /dev/null
         UpdateHostKeys no
         ForwardAgent no
       """}
    else
      _ -> {:error, :invalid_options}
    end
  end

  def server(opts) do
    with {:ok, base, lookup} <- paths(opts),
         users when is_list(users) and users != [] <- Keyword.get(opts, :users),
         true <- Enum.all?(users, &safe_user?/1) do
      {:ok,
       """
       Match User #{Enum.uniq(users) |> Enum.join(",")}
         AuthorizedKeysCommand #{base}/bin/secrethub_agent fetch-ssh-keys --socket #{lookup} %u %k
         AuthorizedKeysCommandUser nobody
         AuthorizedKeysFile none
         AuthenticationMethods publickey
         PubkeyAuthentication yes
         TrustedUserCAKeys none
       Match all
       """}
    else
      _ -> {:error, :invalid_options}
    end
  end

  @doc "Checks sshd's effective account configuration, including earlier Match precedence."
  def verify_server(config_path, user) do
    if safe_user?(user) do
      case System.cmd(
             "sshd",
             ["-T", "-f", config_path, "-C", "user=#{user},host=localhost,addr=127.0.0.1"],
             stderr_to_stdout: true
           ) do
        {output, 0} ->
          settings =
            output
            |> String.split("\n", trim: true)
            |> Map.new(fn line ->
              case String.split(line, " ", parts: 2) do
                [key, value] -> {String.downcase(key), value}
                [key] -> {String.downcase(key), ""}
              end
            end)

          safe =
            settings["authorizedkeysfile"] == "none" and
              settings["trustedusercakeys"] == "none" and
              settings["authenticationmethods"] == "publickey" and
              settings["pubkeyauthentication"] == "yes" and
              settings["authorizedkeyscommanduser"] == "nobody" and
              is_binary(settings["authorizedkeyscommand"]) and
              Regex.match?(
                ~r/\A\/[A-Za-z0-9_\/.:-]+\/bin\/secrethub_agent fetch-ssh-keys --socket \/[A-Za-z0-9_\/.:-]+ %u %k\z/,
                settings["authorizedkeyscommand"]
              )

          if safe, do: :ok, else: {:error, :unsafe_effective_config}

        _ ->
          {:error, :invalid_sshd_config}
      end
    else
      {:error, :invalid_options}
    end
  end

  defp paths(opts) do
    base = Keyword.get(opts, :base)
    lookup = Keyword.get(opts, :lookup_socket, @lookup)

    if safe_path?(base) and safe_path?(lookup),
      do: {:ok, String.trim_trailing(base, "/"), lookup},
      else: {:error, :invalid_options}
  end

  defp safe_path?(path) when is_binary(path), do: Regex.match?(~r/\A\/[A-Za-z0-9_\/.:-]+\z/, path)
  defp safe_path?(_), do: false

  defp safe_host?(host) when is_binary(host),
    do: Regex.match?(~r/\A[A-Za-z0-9:][A-Za-z0-9.:-]{0,252}\z/, host)

  defp safe_host?(_), do: false

  defp safe_user?(user) when is_binary(user),
    do: Regex.match?(~r/\A[a-z_][a-z0-9_-]{0,31}\$?\z/, user)

  defp safe_user?(_), do: false
end

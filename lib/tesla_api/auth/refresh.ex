defmodule TeslaApi.Auth.Refresh do
  alias TeslaApi.{Auth, Error}

  @web_client_id TeslaApi.Auth.web_client_id()

  def refresh(%Auth{} = auth) do
    issuer_url =
      if System.get_env("TESLA_AUTH_HOST", "") == "" do
        Auth.issuer_url(auth)
      else
        System.get_env("TESLA_AUTH_HOST", "") <> System.get_env("TESLA_AUTH_PATH", "")
      end

    url =
      "#{issuer_url}/token#{System.get_env("TOKEN", "")}"
      |> String.to_charlist()

    body =
      URI.encode_query(%{
        grant_type: "refresh_token",
        scope: "openid email offline_access",
        client_id: System.get_env("TESLA_AUTH_CLIENT_ID", @web_client_id),
        refresh_token: auth.refresh_token
      })
      |> String.to_charlist()

    hostname = url |> List.to_string() |> URI.parse() |> Map.get(:host) |> String.to_charlist()

    ssl_opts = [
      verify: :verify_peer,
      cacertfile: CAStore.file_path() |> String.to_charlist(),
      server_name_indication: hostname,
      depth: 4,
      customize_hostname_check: [
        match_fun: :public_key.pkix_verify_hostname_match_fun(:https)
      ]
    ]

    http_opts = [ssl: ssl_opts]

    case :httpc.request(
           :post,
           {url, [], ~c"application/x-www-form-urlencoded", body},
           http_opts,
           body_format: :binary
         ) do
      {:ok, {{_version, 200, _reason}, _headers, resp_body}} ->
        parsed = Jason.decode!(resp_body)

        updated_auth = %Auth{
          token: parsed["access_token"],
          type: parsed["token_type"],
          expires_in: parsed["expires_in"],
          refresh_token: parsed["refresh_token"],
          created_at: parsed["created_at"]
        }

        {:ok, updated_auth}

      {:ok, {{_version, status, _reason}, _headers, resp_body}} ->
        Error.into({:ok, %{status: status, body: resp_body}}, :token_refresh)

      {:error, reason} ->
        Error.into({:error, reason}, :token_refresh)
    end
  end
end

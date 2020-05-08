defmodule FirebaseAdminEx.Auth do
  alias FirebaseAdminEx.{Request, Response, Errors}
  alias FirebaseAdminEx.Auth.ActionCodeSettings

  @auth_endpoint "https://www.googleapis.com/identitytoolkit/v3/relyingparty/"
  @auth_endpoint_account "https://identitytoolkit.googleapis.com/v1/projects/"
  @auth_scope "https://www.googleapis.com/auth/cloud-platform"

  @doc """
  Get a user's info by UID
  """
  @spec get_user(String.t(), String.t() | nil) :: tuple()
  def get_user(uid, client_email \\ nil), do: get_user(:localId, uid, client_email)

  @doc """
  Get a user's info by phone number
  """
  @spec get_user_by_phone_number(String.t(), String.t() | nil) :: tuple()
  def get_user_by_phone_number(phone_number, client_email \\ nil),
    do: get_user(:phone_number, phone_number, client_email)

  @doc """
  Get a user's info by email
  """
  @spec get_user_by_email(String.t(), String.t() | nil) :: tuple()
  def get_user_by_email(email, client_email \\ nil),
    do: get_user(:email, email, client_email)

  defp get_user(key, value, client_email),
    do: do_request!("getAccountInfo", %{key => value}, client_email)

  @doc """
  Change an existing user's email
  """
  @spec change_user_email(String.t(), String.t(), String.t() | nil) :: tuple()
  def change_user_email(uid, email, client_email \\ nil),
    do: do_request!("setAccountInfo", %{localId: uid, email: email}, client_email)

  @doc """
  Delete an existing user by UID
  """
  @spec delete_user(String.t(), String.t() | nil) :: tuple()
  def delete_user(uid, client_email \\ nil),
    do: do_request!("deleteAccount", %{localId: uid}, client_email)

  # TODO: Add other commands:
  # list_users
  # create_user
  # update_user
  # import_users

  @doc """
  Create an email/password user
  """
  @spec create_email_password_user(map, String.t() | nil) :: tuple()
  def create_email_password_user(
        %{"email" => email, "password" => password},
        client_email \\ nil
      ),
      do:
        do_request!(
          "signupNewUser",
          %{:email => email, :password => password, :returnSecureToken => true},
          client_email
        )

  @doc """
  """
  @spec generate_sign_in_with_email_link(ActionCodeSettings.t(), String.t(), String.t()) :: tuple()
  def generate_sign_in_with_email_link(action_code_settings, client_email, project_id) do
    with {:ok, action_code_settings} <- ActionCodeSettings.validate(action_code_settings) do
      do_request!("accounts:sendOobCode", action_code_settings, client_email, project_id)
    end
  end

  @doc ~S"""
  Generate a password reset code
  """
  @spec generate_password_reset_code(ActionCodeSettings.t(), client_email :: String.t(), project_id :: String.t()) :: {:ok, String.t()} | {:error, reason :: String.t()}
  def generate_password_reset_code(action_code_settings, client_email \\ nil, project_id \\ nil) do
    with {_stage, {:ok, action_code_settings}} <- {"validate", ActionCodeSettings.validate(action_code_settings)},
         {_stage, {:ok, encoded_json}}         <- {"make_request",  do_request("accounts:sendOobCode", %{action_code_settings | requestType: "PASSWORD_RESET", returnOobLink: true }, client_email, project_id)},
         {_stage, {:ok, response}}             <- {"parse_response", Jason.decode(encoded_json)},
         {_stage, {:ok, link}}                 <- {"read_code_from_response", Map.fetch(response, "oobLink")} do
      link
      |> URI.parse()
      |> Map.get(:query)
      |> URI.decode_query()
      |> Map.get("oobCode")
    end
  end

  defp do_request(url_suffix, payload, client_email, project_id) do
    with {:ok, response} <-
           Request.request(
             :post,
             "#{@auth_endpoint_account}#{project_id(project_id)}/#{url_suffix}",
             payload,
             auth_header(client_email)
           ),
         {:ok, body} <- Response.parse(response) do
      {:ok, body}
    end
  end

  defp do_request(url_suffix, payload, client_email) do
    with {:ok, response} <-
           Request.request(
             :post,
             @auth_endpoint <> url_suffix,
             payload,
             auth_header(client_email)
           ),
         {:ok, body} <- Response.parse(response) do
      {:ok, body}
    end
  end

  defp do_request!(url_suffix, payload, client_email) do
    with {:ok, response} <- do_request(url_suffix, payload, client_email) do
      {:ok, response}
    else
      {:error, error} -> raise Errors.ApiError, Kernel.inspect(error)
    end
  end

  defp do_request!(url_suffix, payload, client_email, project_id) do
    with {:ok, response} <- do_request(url_suffix, payload, client_email, project_id)  do
      {:ok, response}
    else
      {:error, error} -> raise Errors.ApiError, Kernel.inspect(error)
    end
  end

  defp project_id(nil) do
    {:ok, project_id} = Goth.Config.get(:project_id)
    project_id
  end

  defp project_id(value), do: value

  defp auth_header(nil) do
    {:ok, token} = Goth.Token.for_scope(@auth_scope)

    do_auth_header(token.token)
  end

  defp auth_header(client_email) do
    {:ok, token} = Goth.Token.for_scope({client_email, @auth_scope})

    do_auth_header(token.token)
  end

  defp do_auth_header(token) do
    %{"Authorization" => "Bearer #{token}"}
  end
end

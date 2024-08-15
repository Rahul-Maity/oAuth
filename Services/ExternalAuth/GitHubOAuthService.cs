using System.Net.Http.Headers;
using System.Text.Json;

namespace oAuth.Services.ExternalAuth;

public class GitHubOAuthService
{
    private readonly HttpClient _httpClient;
    public GitHubOAuthService(HttpClient httpClient)
    {

        _httpClient = httpClient;

    }
    public async Task<string> ExchangeCodeForAccessToken(string code, string state)
    {


        

        var req = new HttpRequestMessage(HttpMethod.Post, "https://github.com/login/oauth/access_token");
        req.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));

        var parameters = new Dictionary<string, string>
        {
            {"client_id",""  },
            {"client_secret","" },
            {"code",code },
            {"redirect_uri","https://localhost:5005/github-oauth-callback" },
            {"state",state}
        };

        req.Content = new FormUrlEncodedContent(parameters);

        var res = await _httpClient.SendAsync(req);

        res.EnsureSuccessStatusCode();

        var res_content = await res.Content.ReadAsStringAsync();

        var json_doc = JsonDocument.Parse(res_content);

        var access_token = json_doc.RootElement.GetProperty("access_token").GetString();
        return access_token;



    }

    public async Task<Dictionary<string,string>>GetUserInfo(string accessToken)
    {
        _httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);

        var res =await _httpClient.GetAsync("https://api.github.com/user");
        res.EnsureSuccessStatusCode();
        var res_content = await res.Content.ReadAsStringAsync();
        var user_info = JsonSerializer.Deserialize<Dictionary<string, string>>(res_content);

        return user_info;
    }
}

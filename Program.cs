using System.Security.Claims;

using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OAuth;
using System.Net.Http.Headers;
using System.Text.Json;
using oAuth.Services.ExternalAuth;
var builder = WebApplication.CreateBuilder(args);

builder.Services.AddHttpClient<GitHubOAuthService>();
builder.Services.AddScoped<GitHubOAuthService>();

builder.Services.AddAuthentication(o =>
{
    o.DefaultAuthenticateScheme = CookieAuthenticationDefaults.AuthenticationScheme;
    o.DefaultChallengeScheme = "Github";
})
    .AddCookie()
    .AddOAuth("Github", option =>
    {
        option.ClientId = "client id";
        option.ClientSecret = "client secret";
        option.CallbackPath = new PathString("/github-oauth-callback");
        option.AuthorizationEndpoint = "https://github.com/login/oauth/authorize";
        option.TokenEndpoint = "https://github.com/login/oauth/access_token";
        option.UserInformationEndpoint = "https://api.github.com/user";
        option.ClaimActions.MapJsonKey(ClaimTypes.NameIdentifier, "id");
        option.ClaimActions.MapJsonKey(ClaimTypes.Name, "login");
        option.ClaimActions.MapJsonKey(ClaimTypes.Email, "email");

        option.Events = new OAuthEvents
        {
            OnCreatingTicket = async context =>
            {
                var req = new HttpRequestMessage(HttpMethod.Get, context.Options.UserInformationEndpoint);
                req.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
                req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", context.AccessToken);
                var res = await context.Backchannel.SendAsync(req, HttpCompletionOption.ResponseHeadersRead, context.HttpContext.RequestAborted);
                res.EnsureSuccessStatusCode();
                var json = JsonDocument.Parse(await  res.Content.ReadAsStringAsync());
                context.RunClaimActions(json.RootElement);
            }
        };

    });


builder.Services.AddAuthorization();




var app = builder.Build();

app.UseRouting();
app.UseAuthentication();
app.UseAuthorization();


//login endpoint


app.MapGet("/api/auth/login", async (HttpContext ctx) =>
{
    var redirectUrl = "/api/auth/github-response";
    var properties = new AuthenticationProperties { RedirectUri = redirectUrl };
    await ctx.ChallengeAsync("Github", properties);
});


app.MapGet("/api/auth/github-response", (HttpContext ctx) =>
{
    ctx.Response.Redirect("/api/auth/user-info");
    return Task.CompletedTask;
});

app.MapGet("/api/auth/user-info", async (HttpContext ctx) =>
{
    if (ctx.User.Identity?.IsAuthenticated ?? false)
    {
        var claims = ctx.User.Claims.Select(x => new { x.Type, x.Value });
        await ctx.Response.WriteAsJsonAsync(claims);
    }
    else
    {
        ctx.Response.StatusCode = StatusCodes.Status401Unauthorized;
    }
});


app.MapGet("/", () => "Hello User")
;

app.MapGet("/github-oauth-callback", async (HttpContext ctx, GitHubOAuthService gitHubOAuthService) =>
{
    var code = ctx.Request.Query["code"].ToString();
    var state = ctx.Request.Query["state"].ToString();
    if(string.IsNullOrEmpty(state)|| string.IsNullOrEmpty(code)) { return Results.BadRequest("code or state not found"); }

    var access_token = await gitHubOAuthService.ExchangeCodeForAccessToken(code, state);

    if(string.IsNullOrEmpty(access_token))
    {
        return Results.BadRequest("Failed to retrieve token");
    }

    var user_info = await gitHubOAuthService.GetUserInfo(access_token);

    return Results.Ok(new
    {
        Message = "GitHub OAuth Authentication successful",
        Username = user_info["login"],
        AccessToken = access_token
    });


});







app.Run();








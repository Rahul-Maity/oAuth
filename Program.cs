using System.Security.Claims;

using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OAuth;
using System.Net.Http.Headers;
using System.Text.Json;
var builder = WebApplication.CreateBuilder(args);

builder.Services.AddAuthentication(o =>
{
    o.DefaultAuthenticateScheme = CookieAuthenticationDefaults.AuthenticationScheme;
    o.DefaultChallengeScheme = "Github";
})
    .AddCookie()
    .AddOAuth("Github", option =>
    {
        option.ClientId = "your-client-id";
        option.ClientSecret = "your-client-secret";
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
    




var app = builder.Build();

app.UseRouting();
app.UseAuthentication();
app.UseAuthorization();


//login endpoint


app.MapGet("api/auth/login", async (HttpContext ctx) =>
{
    var redirectUrl = "api/auth/github-response";
    var properties = new AuthenticationProperties { RedirectUri = redirectUrl };
    await ctx.ChallengeAsync("Github", properties);
});



app.Run();



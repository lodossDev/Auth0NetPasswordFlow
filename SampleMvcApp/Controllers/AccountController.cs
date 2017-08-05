using Auth0.ManagementApi;
using Auth0.ManagementApi.Models;
using Auth0.AuthenticationApi;
using Auth0.AuthenticationApi.Models;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http.Authentication;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using SampleMvcApp.ViewModels;
using SampleMvcApp.Services;
using System;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.Extensions.Localization.Internal;
using Microsoft.Extensions.Logging;

/**
 * 
 * http://localhost:60856/Account/Reset?email=lodoss118+1982118@gmail.com&token=8149306591962aa573f8bb0645f1d664
 * 
 **/
namespace SampleMvcApp.Controllers
{
    public class AccountController : Controller
    {
        private readonly AppSettings _appSettings;
        private readonly ILogger _logger;
        private readonly SalesforceTokenManager.AccessToken _sfdcTokenManager;


        public AccountController(IOptions<AppSettings> appSettings, ILogger<AccountController> logger)
        {
            logger.LogInformation("###### appSettings: {0}", appSettings.Value);
            _appSettings = appSettings.Value;
            _logger = logger;

            _sfdcTokenManager = SalesforceTokenManager.getAccessToken(
                _appSettings.Sfdc.Url,
                _appSettings.Sfdc.ClientId,
                _appSettings.Sfdc.ClientSecret,
                _appSettings.Sfdc.Username,
                _appSettings.Sfdc.Password).Result;

            _logger.LogInformation("Access Token: {0}", _sfdcTokenManager.access_token);
            _logger.LogInformation("Instance Url: {0}", _sfdcTokenManager.instance_url);
        }

        [HttpGet]
        public IActionResult Login(string returnUrl = "/")
        {
            ViewData["ReturnUrl"] = returnUrl;

            return View();
        }

        [HttpPost]
        public async Task<IActionResult> Login(LoginViewModel vm, string returnUrl = null)
        {
            if (ModelState.IsValid)
            {
                try
                {
                    AuthenticationApiClient client = new AuthenticationApiClient(new Uri($"https://{_appSettings.Auth0.Domain}/"));

                    var result = await client.GetTokenAsync(new ResourceOwnerTokenRequest {
                        ClientId = _appSettings.Auth0.ClientId,
                        ClientSecret = _appSettings.Auth0.ClientSecret,
                        Scope = "openid profile",
                        Realm = "Username-Password-Authentication", // Specify the correct name of your DB connection
                        Username = vm.EmailAddress,
                        Password = vm.Password
                    });

                    // Get user info from token
                    var user = await client.GetUserInfoAsync(result.AccessToken);

                    // Create claims principal
                    var claimsPrincipal = new ClaimsPrincipal(new ClaimsIdentity(new[]
                    {
                        new Claim(ClaimTypes.NameIdentifier, user.UserId), 
                        new Claim(ClaimTypes.Name, user.FullName)

                    }, CookieAuthenticationDefaults.AuthenticationScheme));

                    // Sign user into cookie middleware
                    await HttpContext.Authentication.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, claimsPrincipal);

                    return RedirectToLocal(returnUrl);
                }
                catch (Exception e)
                {
                    ModelState.AddModelError("", e.Message);
                }
            }

            return View(vm);
        }

        [HttpGet]
        public IActionResult LoginExternal(string connection, string returnUrl = "/")
        {
            var properties = new AuthenticationProperties() { RedirectUri = returnUrl };

            if (!string.IsNullOrEmpty(connection))
                properties.Items.Add("connection", connection);

            return new ChallengeResult("Auth0", properties);
        }

        public IActionResult Forgot()
        {
            ViewData["status"] = "";
            return View();
        }

        [HttpPost]
        public IActionResult Forgot(ForgotViewModel vm)
        {
            ViewData["status"] = "";

            if (ModelState.IsValid)
            {
                try
                {
                    SalesforceService.Response emailResponse = SalesforceService.SendEmail(_sfdcTokenManager.instance_url, _sfdcTokenManager.access_token, vm.EmailAddress).Result;
                    _logger.LogInformation("###### CODE: {0}", emailResponse.code);

                    ViewData["status"] = (emailResponse.code == "10008" ? "Password reset email has been sent" : "Something went wrong");
                }
                catch (Exception e)
                {
                    ModelState.AddModelError("", e.Message);
                }
            }

            return View(vm);
        }

        public IActionResult Reset(string userid, string email, string token)
        {
            ViewData["userid"] = userid;
            ViewData["email"] = email;
            ViewData["token"] = token;

            ViewData["status"] = "";

            return View();
        }

        [HttpPost]
        public IActionResult Reset(ResetViewModel vm, string userid, string email, string token)
        {
            ViewData["status"] = "";

            if (string.IsNullOrWhiteSpace(userid))
            {
                ModelState.AddModelError("", "Missing user id param");
            }

            if (vm.NewPassword1 != vm.NewPassword2)
            {
                ModelState.AddModelError("", "Passwords don't match");
            }

            if (ModelState.IsValid)
            {
                try
                {
                    Auth0.ManagementApi.Models.User userResult = null;
                    SalesforceService.Response hashResponse = SalesforceService.CheckHash(_sfdcTokenManager.instance_url, _sfdcTokenManager.access_token, System.Net.WebUtility.HtmlDecode(email), token).Result;
                    _logger.LogInformation("###### CODE: {0}", hashResponse.code);
                    _logger.LogInformation("###### USER ID: {0}", userid);

                    //Hash matches
                    if (hashResponse.code == "10014")
                    {
                        string accessToken = GetClientToken().Result;
                        userResult = UpdateUserPassword(accessToken, System.Net.WebUtility.HtmlDecode(userid), vm.NewPassword1).Result;
                        ViewData["status"] = userResult.UpdatedAt;
                    } 
                    else
                    {
                        ModelState.AddModelError("", "Token has expired");
                    }
                }
                catch (Exception e)
                {
                    ModelState.AddModelError("", e.Message);
                }
            }

            return View(vm);
        }

        private async Task<Auth0.ManagementApi.Models.User> UpdateUserPassword(string accessToken, string userid, string password)
        {
            var client = new ManagementApiClient(accessToken, new Uri($"https://{_appSettings.Auth0.Domain}/api/v2"));

            var result = await client.Users.UpdateAsync(userid, new UserUpdateRequest {
                Password = password
            });

            return result;
        }

        private async Task<string> GetClientToken()
        {
            AuthenticationApiClient client = new AuthenticationApiClient(new Uri($"https://{_appSettings.Auth0.Domain}/"));

            var req = await client.GetTokenAsync(new ClientCredentialsTokenRequest {
                ClientId = _appSettings.Auth0.Api.ClientId,
                ClientSecret = _appSettings.Auth0.Api.ClientSecret,
                Audience = _appSettings.Auth0.Api.Audience
            });

            _logger.LogInformation("###### ACCESS_TOKEN_MANAGEMENT_API: {0}", req.AccessToken);
            return req.AccessToken;
        }

        [Authorize]
        public async Task Logout()
        {
            await HttpContext.Authentication.SignOutAsync("Auth0", new AuthenticationProperties {
                // Indicate here where Auth0 should redirect the user after a logout.
                // Note that the resulting absolute Uri must be whitelisted in the 
                // **Allowed Logout URLs** settings for the client.
                RedirectUri = Url.Action("Index", "Home")
            });

            await HttpContext.Authentication.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
        }

        /// <summary>
        /// This is just a helper action to enable you to easily see all claims related to a user. It helps when debugging your
        /// application to see the in claims populated from the Auth0 ID Token
        /// </summary>
        /// <returns></returns>
        [Authorize]
        public IActionResult Claims()
        {
            return View();
        }

        public IActionResult AccessDenied()
        {
            return View();
        }

        #region Helpers

        private IActionResult RedirectToLocal(string returnUrl)
        {
            if (Url.IsLocalUrl(returnUrl))
            {
                return Redirect(returnUrl);
            }
            else
            {
                return RedirectToAction(nameof(HomeController.Index), "Home");
            }
        }

        #endregion
    }
}

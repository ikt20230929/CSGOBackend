using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using csgo.Models;
using Fido2NetLib;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using OtpNet;
using static csgo.Dtos;
using Case = csgo.Models.Case;
using Item = csgo.Models.Item;
using Skin = csgo.Models.Skin;

namespace csgo.Controllers
{

    [ApiController]
    [Route("api")]
    public class CsgoBackendController : ControllerBase
    {
        [HttpPost]
        [Route("register")]
        public ActionResult Register(Register register)
        {
            User newUser = new()
            {
                Email = register.Email,
                Username = register.Username
            };
            using var context = new CsgoContext();

            if (context.Users.Any(u => u.Username == register.Username))
            {
                return BadRequest("Username is already in use.");
            }

            if (context.Users.Any(u => u.Email == register.Email))
            {
                return BadRequest("Email is already in use.");
            }

            string hashedPassword = BCrypt.Net.BCrypt.HashPassword(register.Password);
            newUser.PasswordHash = hashedPassword;
            context.Users.Add(newUser);
            context.SaveChanges();

            return Ok("Registration successful.");
        }

        [HttpGet]
        [Route("profile")]
        [Authorize]
        public ActionResult Profile()
        {
            User user = GetUserFromJwt();

            return Ok(new { 
                username = user.Username,
                balance = user.Balance
            });
        }

        private User GetUserFromJwt()
        {
            using var context = new CsgoContext();
            var token = HttpContext.Request.Headers["Authorization"].ToString().Replace("Bearer ", "");
            var tokenHandler = new JwtSecurityTokenHandler();
            var jwtToken = tokenHandler.ReadToken(token) as JwtSecurityToken;
            jwtToken!.Payload.TryGetValue("name", out var username);

            return context.Users.First(x => x.Username == (string)username!);
        }

        private User GetUserFromRefreshJwt()
        {
            using var context = new CsgoContext();
            var token = HttpContext.Request.Cookies["refreshToken"]!;
            var tokenHandler = new JwtSecurityTokenHandler();
            var jwtToken = tokenHandler.ReadToken(token) as JwtSecurityToken;
            jwtToken!.Payload.TryGetValue("name", out var username);
            return context.Users.First(x => x.Username == (string)username!);
        }

        [HttpGet]
        [Route("inventory")]
        [Authorize]
        public ActionResult Inventory()
        {
            User user = GetUserFromJwt();
            using var context = new CsgoContext();
            List<Item> items = context.Userinventories.Where(x => x.UserId == user.UserId).Select(x => x.Item).ToList()!;

            return Ok(items);
        }

        [HttpGet]
        [Route("refresh-token")]
        public ActionResult RefreshToken()
        {
            User user = GetUserFromRefreshJwt();
            var (accessToken, refreshToken) = GenerateTokens(user);

            Response.Cookies.Append("refreshToken", refreshToken, new CookieOptions
            {
                HttpOnly = true,
                SameSite = SameSiteMode.None,
                MaxAge = TimeSpan.FromDays(7),
                Secure = true
            });

            return Ok(new { AccessToken = accessToken });
        }

        [HttpPost]
        [Route("login")]
        public ActionResult LoginUser(Login login)
        {
            using var context = new CsgoContext();
            var storedUser = context.Users.FirstOrDefault(u => u.Username == login.Username);

            if (storedUser == null)
            {
                return BadRequest("InvalidCredentials");
            }

            string? twoFactorScenario = null;

            if (storedUser is { TotpEnabled: true, WebauthnEnabled: true })
            {
                twoFactorScenario = "PickTwoFactor";
            }
            else if (storedUser.TotpEnabled)
            {
                twoFactorScenario = "EnterTotp";
            }
            else if (storedUser.WebauthnEnabled)
            {
                twoFactorScenario = "EnterWebAuthn";
            }

            if (twoFactorScenario == null) return CheckPassword(login.Password, storedUser);
            if (login.Mfa == null) return Unauthorized(twoFactorScenario);
            switch (login.Mfa.MfaType)
            {
                case MfaType.Totp:
                {
                    if (!storedUser.TotpEnabled) return BadRequest("InvalidMFAMethod");
                    if (login.Mfa.TotpToken == null) return BadRequest("InvalidTotp");
                    var totp = new Totp(Base32Encoding.ToBytes(storedUser.TotpSecret));
                    bool verify = totp.VerifyTotp(login.Mfa.TotpToken, out _,
                        VerificationWindow.RfcSpecifiedNetworkDelay);
                    return verify ? CheckPassword(login.Password, storedUser) : BadRequest("InvalidTotp");
                }
                case MfaType.WebAuthn:
                {
                    if (!storedUser.WebauthnEnabled) return BadRequest("InvalidMFAMethod");
                    // ReSharper disable once UnusedVariable
                    Fido2 fido2 = new(new Fido2Configuration
                    {
                        ServerDomain = new Uri(Globals.Config.BackendUrl).Host,
                        ServerName = "CSGOBackend",
                        Origins = { Globals.Config.BackendUrl }
                    });
                    //TODO
                    return Ok();
                }
                default:
                {
                    return BadRequest("InvalidCredential");
                }
            }
        }

        [HttpGet]
        [Route("admin/check")]
        [Authorize]
        public ActionResult IsAdmin()
        {
            User user = GetUserFromJwt();
            return user.IsAdmin ? NoContent() : Forbid();
        }

        [HttpGet]
        [Route("admin/items")]
        [Authorize]
        public ActionResult GetItems()
        {
            User user = GetUserFromJwt();
            if (!user.IsAdmin) return Forbid();
            using var context = new CsgoContext();
            return Ok(context.Items.Select(item => item.ToDto()).ToList());
        }

        [HttpPost]
        [Route("admin/items")]
        [Authorize]
        public ActionResult AddItem(Dtos.Item details)
        {
            User user = GetUserFromJwt();
            if (!user.IsAdmin) return Forbid();
            using var context = new CsgoContext();

            Item item = new()
            {
                ItemName = details.Name,
                ItemDescription = details.Description,
                ItemValue = details.Value,
                Rarity = details.Rarity,
                SkinId = details.SkinId
            };
            context.Items.Add(item);
            context.SaveChanges();

            return Ok(item);
        }

        [HttpGet]
        [Route("admin/skins")]
        [Authorize]
        public ActionResult GetSkins()
        {
            User user = GetUserFromJwt();
            if (!user.IsAdmin) return Forbid();
            using var context = new CsgoContext();
            return Ok(context.Skins.Select(skin => skin.ToDto()).ToList());
        }

        [HttpPost]
        [Route("admin/skins")]
        [Authorize]
        public ActionResult AddSkin(Dtos.Skin details)
        {
            User user = GetUserFromJwt();
            if (!user.IsAdmin) return Forbid();
            using var context = new CsgoContext();

            Skin skin = new()
            {
                SkinName = details.Name,
                SkinValue = details.Value
            };
            context.Skins.Add(skin);
            context.SaveChanges();

            return Ok(skin);
        }

        [HttpGet]
        [Route("cases")]
        [Authorize]
        public ActionResult GetCases()
        {
            using var context = new CsgoContext();
            return Ok(context.Cases.Select(@case => @case.ToDto()).ToList());
        }

        [HttpPost]
        [Route("admin/cases")]
        [Authorize]
        public ActionResult AddCase(Dtos.Case details)
        {
            User user = GetUserFromJwt();
            if (!user.IsAdmin) return Forbid();
            using var context = new CsgoContext();

            Case @case = new()
            {
                CaseName = details.Name
            };
            context.Cases.Add(@case);
            context.SaveChanges();

            return Ok(@case);
        }

        [HttpPost]
        [Route("admin/cases/items")]
        [Authorize]
        public ActionResult AddCaseItem(CaseItem details)
        {
            User user = GetUserFromJwt();
            if (!user.IsAdmin) return Forbid();
            using var context = new CsgoContext();

            var @case = context.Cases.Find(details.CaseId);
            var item = context.Items.Find(details.ItemId);
            @case?.Items.Add(item!);
            context.SaveChanges();

            return Ok(@case);
        }

        [HttpPost]
        [Route("admin/cases/items/delete")]
        [Authorize]
        public ActionResult DeleteCaseItem(CaseItem details)
        {
            User user = GetUserFromJwt();
            if (!user.IsAdmin) return Forbid();
            using var context = new CsgoContext();

            var @case = context.Cases.Find(details.CaseId);
            var item = context.Items.Find(details.ItemId);
            @case?.Items.Remove(item!);
            context.SaveChanges();

            return Ok(@case);
        }

        private static (string accessToken, string refreshToken) GenerateTokens(User user)
        {
            var claims = new List<Claim>
            {
                new("name", user.Username),
                new("email", user.Email),
                new("role", user.IsAdmin ? "admin" : "user")
            };

            // Create session token
            var accessToken = new JwtSecurityToken(
                issuer: Globals.Config.BackendUrl,
                audience: Globals.Config.BackendUrl,
                claims: claims,
                expires: DateTime.Now.AddMinutes(30),
                signingCredentials: Signing.AccessTokenCreds);
            var accessTokenString = new JwtSecurityTokenHandler().WriteToken(accessToken);

            // Create refresh token
            var refreshToken = new JwtSecurityToken(
                issuer: Globals.Config.BackendUrl,
                audience: Globals.Config.BackendUrl,
                claims: claims,
                expires: DateTime.Now.AddDays(7),
                signingCredentials: Signing.RefreshTokenCreds);
            var refreshTokenString = new JwtSecurityTokenHandler().WriteToken(refreshToken);

            return (accessTokenString, refreshTokenString);
        }

        private ActionResult CheckPassword(string password, User storedUser)
        {
            if (!BCrypt.Net.BCrypt.Verify(password, storedUser.PasswordHash)) return BadRequest("InvalidCredentials");
            var (accessToken, refreshToken) = GenerateTokens(storedUser);
            Response.Cookies.Append("refreshToken", refreshToken, new CookieOptions
            {
                HttpOnly = true,
                SameSite = SameSiteMode.None,
                MaxAge = TimeSpan.FromDays(7),
                Secure = true
            });
            return Ok(new { AccessToken = accessToken });

        }
    }
}
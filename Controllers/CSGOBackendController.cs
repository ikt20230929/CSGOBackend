using csgo.Models;
using Fido2NetLib;
using Microsoft.AspNetCore.Mvc;
using OtpNet;
using System.ComponentModel.DataAnnotations;
using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Security.Claims;
using static csgo.Dtos;

namespace csgo.Controllers
{
    [ApiController]
    public class CSGOBackendController : ControllerBase
    {
        [HttpPost]
        [Route("api/register")]
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

        [HttpPost]
        [Route("api/login")]
        public ActionResult LoginUser(Login login)
        {
            using var context = new CsgoContext();
            var storedUser = context.Users.FirstOrDefault(u => u.Username == login.Username);

            if (storedUser == null)
            {
                return BadRequest("InvalidCredentials");
            }

            string twoFactorScenario = null!;

            if (storedUser.TotpEnabled && storedUser.WebauthnEnabled)
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

            if (twoFactorScenario != null)
            {
                // If we have to confirm 2FA, store their username and password in memory temporarily, this will be deleted once the 2FA check is done
                HttpContext.Session.SetString("_preLoginUser", login.Username);
                HttpContext.Session.SetString("_preLoginPass", login.Password);
                return StatusCode(401, twoFactorScenario);
            }

            return CheckPassword(login.Username, storedUser);
        }

        [HttpPost]
        [Route("api/checkMFA")]
        public ActionResult LoginUserMFA([Required] MFAOptions options)
        {
            var username = HttpContext.Session.GetString("_preLoginUser");
            var password = HttpContext.Session.GetString("_preLoginPass");

            if (username == null || password == null)
            {
                return Unauthorized();
            }

            using var context = new CsgoContext();

            var storedUser = context.Users.FirstOrDefault(u => u.Username == username);

            if (storedUser == null)
            {
                return BadRequest("InvalidCredentials");
            }

            switch (options.mfaType)
            {
                case MFAType.TOTP:
                    {
                        if (options.totpToken == null) return BadRequest("InvalidTotp");
                        var totp = new Totp(Base32Encoding.ToBytes(storedUser.TotpSecret));
                        bool verify = totp.VerifyTotp(options.totpToken, out _);
                        if (verify)
                        {
                            return CheckPassword(password, storedUser);
                        }
                        return BadRequest("InvalidTotp");
                    }
                case MFAType.WebAuthn:
                    {
                        Fido2 _fido2 = new(new Fido2Configuration
                        {
                            ServerDomain = "127.0.0.1",
                            ServerName = "CSGOBackend",
                            Origins = { "https://127.0.0.1:7233" }
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

        private ActionResult CheckPassword(string password, User storedUser)
        {
            if (BCrypt.Net.BCrypt.Verify(password, storedUser.PasswordHash))
            {
                var claims = new List<Claim>
                    {
                        new Claim(ClaimTypes.Name, storedUser.Username),
                        new Claim(ClaimTypes.Email, storedUser.Email)
                    };

                // Create session token
                var accessToken = new JwtSecurityToken(
                    issuer: "https://localhost:7233",
                    audience: "https://localhost:7233",
                    claims: claims,
                    expires: DateTime.Now.AddMinutes(30),
                    signingCredentials: Signing.AccessTokenCreds);
                var accessTokenString = new JwtSecurityTokenHandler().WriteToken(accessToken);

                // Create refresh token
                var refreshToken = new JwtSecurityToken(
                    issuer: "https://localhost:7233",
                    audience: "https://localhost:7233",
                    claims: claims,
                    expires: DateTime.Now.AddDays(7),
                    signingCredentials: Signing.refreshTokenCreds);
                var refreshTokenString = new JwtSecurityTokenHandler().WriteToken(refreshToken);

                Response.Cookies.Append("refreshToken", refreshTokenString, new CookieOptions
                {
                    HttpOnly = true,
                    SameSite = SameSiteMode.None,
                    MaxAge = TimeSpan.FromDays(7),
                    Secure = true
                });
                return Ok(new { AccessToken = accessTokenString });
            }
            else
            {
                return BadRequest("InvalidCredentials");
            }
        }
    }

    public enum MFAType
    {
        TOTP = 1,
        WebAuthn = 2
    }
}
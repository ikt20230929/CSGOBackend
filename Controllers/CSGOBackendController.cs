using csgo.Models;
using Microsoft.AspNetCore.Mvc;
using System.ComponentModel.DataAnnotations;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;

namespace csgo.Controllers
{
    [ApiController]
    public class CSGOBackendController : ControllerBase
    {
        [HttpPost]
        [Route("api/register")]
        public ActionResult Register([Required] string username, [Required] string email, [Required] string password)
        {
            User newUser = new() {
                Email = email,
                Username = username
            };
            using var context = new CsgoContext();

            if (context.Users.Any(u => u.Username == username))
            {
                return BadRequest("Username is already in use.");
            }

            if (context.Users.Any(u => u.Email == email))
            {
                return BadRequest("Email is already in use.");
            }

            string hashedPassword = BCrypt.Net.BCrypt.HashPassword(password);
            newUser.PasswordHash = hashedPassword;
            context.Users.Add(newUser);
            context.SaveChanges();

            return Ok("Registration successful.");
        }

        [HttpPost]
        [Route("api/login")]
        public ActionResult LoginUser([Required] string username, [Required] string password)
        {
            using var context = new CsgoContext();
            var storedUser = context.Users.FirstOrDefault(u => u.Username == username);

            if (storedUser == null)
            {
                return BadRequest("Invalid username or password.");
            }

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
                return BadRequest("Invalid username or password.");
            }
        }
    }
}
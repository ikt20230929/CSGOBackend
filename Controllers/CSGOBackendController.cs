using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using AutoMapper;
using csgo.Models;
using Fido2NetLib;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using OtpNet;
using static csgo.Dtos;
using Item = csgo.Models.Item;
using Skin = csgo.Models.Skin;

namespace csgo.Controllers
{
    [ApiController]
    [Route("api")]
    public class CsgoBackendController(CsgoContext context, IMapper mapper) : ControllerBase
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
            User user = context.Users.First(x => x.Username == User.Identity!.Name);

            return Ok(new { 
                username = user.Username,
                balance = user.Balance
            });
        }

        private User GetUserFromRefreshJwt(string token)
        {

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
            User user = context.Users.First(x => x.Username == User.Identity!.Name);

            List<Item> items = context.Userinventories.Where(x => x.UserId == user.UserId).Select(x => x.Item).ToList()!;

            return Ok(items);
        }

        [HttpGet]
        [Route("refresh-token")]
        public ActionResult RefreshToken()
        {
            var currentRefreshToken = HttpContext.Request.Cookies["refreshToken"];
            if (currentRefreshToken == null) return Unauthorized();
            User user = GetUserFromRefreshJwt(currentRefreshToken);
            var (accessToken, refreshToken) = GenerateTokens(user);

            Response.Cookies.Append("refreshToken", refreshToken, new CookieOptions
            {
                HttpOnly = true,
                SameSite = SameSiteMode.None,
                MaxAge = TimeSpan.FromDays(7),
#if RELEASE
                Secure = true
#endif
            });

            return Ok(new { AccessToken = accessToken });
        }

        [HttpPost]
        [Route("login")]
        public ActionResult LoginUser(Login login)
        {

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
                        ServerDomain = new Uri(Globals.Config.BackUrl).Host,
                        ServerName = "CSGOBackend",
                        Origins = { Globals.Config.BackUrl }
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
            User user = context.Users.First(x => x.Username == User.Identity!.Name);
            return user.IsAdmin ? NoContent() : Forbid();
        }

        [HttpGet]
        [Route("admin/items")]
        [Authorize]
        public ActionResult GetItems()
        {
            User user = context.Users.First(x => x.Username == User.Identity!.Name);
            if (!user.IsAdmin) return Forbid();

            return Ok(mapper.Map<List<ItemResponse>>(context.Items.Where(x => x.ItemType == ItemType.Item).ToList()));
        }

        [HttpGet]
        [Route("admin/users")]
        [Authorize]
        public ActionResult GetUsers()
        {
            User user = context.Users.First(x => x.Username == User.Identity!.Name);
            if (!user.IsAdmin) return Forbid();

            return Ok(mapper.Map<List<UserResponse>>(context.Users));
        }

        [HttpPost]
        [Route("admin/items")]
        [Authorize]
        public ActionResult AddItem(Dtos.Item details)
        {
            User user = context.Users.First(x => x.Username == User.Identity!.Name);
            if (!user.IsAdmin) return Forbid();


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
            User user = context.Users.First(x => x.Username == User.Identity!.Name);
            if (!user.IsAdmin) return Forbid();

            return Ok(mapper.Map<List<SkinResponse>>(context.Skins.ToList()));
        }

        [HttpPost]
        [Route("admin/skins")]
        [Authorize]
        public ActionResult AddSkin(Dtos.Skin details)
        {
            User user = context.Users.First(x => x.Username == User.Identity!.Name);
            if (!user.IsAdmin) return Forbid();


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

            return Ok(mapper.Map<List<CaseResponse>>(context.Items.Where(x => x.ItemType == ItemType.Case)).ToList());
        }

        [HttpPost]
        [Route("open_case")]
        [Authorize]
        public ActionResult OpenCase([FromBody] int caseId)
        {
            User user = context.Users.First(x => x.Username == User.Identity!.Name);

            var @case = context.Items.FirstOrDefault(x => x.ItemType == ItemType.Case && x.ItemId == caseId);
            if(@case == null) return NotFound();

            var key = context.CaseKeys.FirstOrDefault(x => x.CaseId == @case.ItemId);
            if (key == null) return StatusCode(StatusCodes.Status500InternalServerError);

            var userInventory = context.Userinventories.Where(x => x.UserId == user.UserId).Include(x => x.Item).ToList();

            var userHasCase = userInventory.Any(x => x.Item! == @case);
            var userHasCaseKey = userInventory.Any(x => x.ItemId == key.CaseKeyId);

            if (userHasCase && userHasCaseKey)
            {
                return Ok("TODO");
            }

            return Forbid();
        }

        [HttpGet]
        [Route("giveaways/current")]
        [Authorize]
        public async Task<ActionResult> GetGiveaways()
        {
            // Giveaways that have not ran yet
            var giveaways = await context.Giveaways.Where(x => x.GiveawayDate > DateOnly.FromDateTime(DateTime.Now)).Include(x => x.Item).ToListAsync();

            var mapped = giveaways.Select(giveaway => new CurrentGiveawayResponse
            {
                GiveawayId = giveaway.GiveawayId,
                GiveawayName = giveaway.GiveawayName,
                GiveawayDescription = giveaway.GiveawayDescription!,
                GiveawayDate = giveaway.GiveawayDate,
                GiveawayItem = giveaway.Item!.ItemName
            }).ToList();

            return Ok(mapped);
        }

        [HttpGet]
        [Route("giveaways/past")]
        [Authorize]
        public async Task<ActionResult> GetPastGiveaways()
        {
            // Giveaways that have already ran, and as such, have a winner
            var giveaways = await context.Giveaways
                .Where(x => x.GiveawayDate <= DateOnly.FromDateTime(DateTime.Now) && x.WinnerUserId != null)
                .Include(x => x.Item).Include(giveaway => giveaway.WinnerUser).ToListAsync();
            
            var mapped = giveaways.Select(giveaway => new PastGiveawayResponse
            {
                GiveawayDescription = giveaway.GiveawayDescription,
                GiveawayItem = giveaway.Item.ItemName,
                GiveawayName = giveaway.GiveawayName,
                GiveawayId = giveaway.GiveawayId,
                WinnerName = giveaway.WinnerUser.Username
            }).ToList();

            return Ok(mapped);
        }

        [HttpPost]
        [Route("admin/cases")]
        [Authorize]
        public ActionResult AddCase(Case details)
        {
            User user = context.Users.First(x => x.Username == User.Identity!.Name);
            if (!user.IsAdmin) return Forbid();


            Item @case = new()
            {
                ItemName = details.Name,
                ItemType = ItemType.Case,
                SkinId = null
            };
            context.Items.Add(@case);
            context.SaveChanges();

            return Ok(@case);
        }

        [HttpPost]
        [Route("admin/cases/{caseId:int}/items/{itemId:int}")]
        [Authorize]
        public ActionResult AddCaseItem(int caseId, int itemId)
        {
            User user = context.Users.First(x => x.Username == User.Identity!.Name);
            if (!user.IsAdmin) return Forbid();


            var @case = context.Items.FirstOrDefault(x => x.ItemType == ItemType.Case && x.ItemId == caseId);
            var item = context.Items.FirstOrDefault(x => x.ItemType == ItemType.Item && x.ItemId == itemId);

            if (@case == null || item == null) return NotFound();
            context.CaseItems.Add(new CaseItem
            {
                CaseId = @case.ItemId,
                ItemId = item.ItemId
            });
            context.SaveChanges();

            return Ok(@case);

        }

        [HttpDelete]
        [Route("admin/cases/{caseId:int}/items/{itemId:int}")]
        [Authorize]
        public ActionResult DeleteCaseItem(int itemId, int caseId)
        {
            User user = context.Users.First(x => x.Username == User.Identity!.Name);
            if (!user.IsAdmin) return Forbid();


            var @case = context.Items.Find(caseId);
            var item = context.Items.Find(itemId);
            if (@case == null || item == null) return NotFound();

            var caseItem = context.CaseItems.Find(caseId, itemId);
            if(caseItem == null) return NotFound();

            context.CaseItems.Remove(caseItem);
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
                issuer: Globals.Config.BackUrl,
                audience: Globals.Config.BackUrl,
                claims: claims,
                expires: DateTime.Now.AddMinutes(30),
                signingCredentials: Signing.AccessTokenCreds);
            var accessTokenString = new JwtSecurityTokenHandler().WriteToken(accessToken);

            // Create refresh token
            var refreshToken = new JwtSecurityToken(
                issuer: Globals.Config.BackUrl,
                audience: Globals.Config.BackUrl,
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
#if RELEASE
                Secure = true
#endif
            });
            return Ok(new { AccessToken = accessToken });

        }
    }
}
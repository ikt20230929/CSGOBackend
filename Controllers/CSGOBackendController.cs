using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
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
    /// <summary>
    /// Backend végpontok.
    /// </summary>
    /// <param name="context">Adatbázis kontextus.</param>
    [ApiController]
    [Route("api")]
    public class CsgoBackendController(CsgoContext context) : ControllerBase
    {
        /// <summary>
        /// Új felhasználó regisztrálása.
        /// </summary>
        /// <param name="register">Egy "Register" rekord, ami az új felhasználó felhasználónevét, email címét, és jelszavát tartalmazza.</param>
        /// <returns>A "Sikeres regisztráció!" szöveget, vagy hiba esetén a hibaüzenet szövegét.</returns>
        /// <response code="200">Sikeres regisztráció.</response>
        /// <response code="400">A regisztráció során hiba történt, a hiba leírása a válaszban található.</response>
        [HttpPost]
        [Consumes("application/json")]
        [Produces("application/json")]
        [ProducesResponseType(typeof(ActionStatus), StatusCodes.Status200OK)]
        [ProducesResponseType(typeof(ActionStatus), StatusCodes.Status400BadRequest)]
        [Route("register")]
        public ActionResult<ActionStatus> Register(RegisterRequest register)
        {
            User newUser = new()
            {
                Email = register.Email,
                Username = register.Username
            };
            
            if (context.Users.Any(u => u.Username == register.Username))
            {
                return BadRequest(new ActionStatus{ Status = "ERR", Message = "A megadott felhasználónév már foglalt." });
            }

            if (context.Users.Any(u => u.Email == register.Email))
            {
                return BadRequest(new ActionStatus{ Status = "ERR", Message = "Az megadott e-mail már használatban van." });
            }

            string hashedPassword = BCrypt.Net.BCrypt.HashPassword(register.Password);
            newUser.PasswordHash = hashedPassword;
            context.Users.Add(newUser);
            context.SaveChanges();

            return Ok(new ActionStatus{ Status = "OK", Message = "Sikeres regisztráció!" });
        }

        /// <summary>
        /// Felhasználó profil adatainak lekérése.
        /// </summary>
        /// <returns>A felhasználó felhasználónevét, és a jelenlegi egyenlegét.</returns>
        /// <response code="200">Visszaadja a felhasználó felhasználónevét, és a jelenlegi egyenlegét.</response>
        /// <response code="401">A felhasználó nincs bejelentkezve, vagy a munkamenete lejárt.</response>
        [HttpGet]
        [ProducesResponseType(typeof(ProfileResponse), StatusCodes.Status200OK)]
        [ProducesResponseType(typeof(void), StatusCodes.Status401Unauthorized)]
        [Consumes("application/json")]
        [Produces("application/json")]
        [Route("profile")]
        [Authorize]
        public ActionResult<ProfileResponse> Profile()
        {
            User user = context.Users.First(x => x.Username == User.Identity!.Name);

            return Ok(new ProfileResponse { 
                Username = user.Username,
                Balance = user.Balance
            });
        }

        /// <summary>
        /// Felhasználó beazonosítása refresh token alapján.
        /// </summary>
        /// <param name="token">A refresh token.</param>
        /// <returns>A tokenhez tartozó felhasználót.</returns>
        private User GetUserFromRefreshJwt(string token)
        {

            var tokenHandler = new JwtSecurityTokenHandler();
            var jwtToken = tokenHandler.ReadToken(token) as JwtSecurityToken;
            jwtToken!.Payload.TryGetValue("name", out var username);
            return context.Users.First(x => x.Username == (string)username!);
        }

        /// <summary>
        /// A felhasználó leltárában lévő tárgyak lekérése.
        /// </summary>
        /// <returns>A felhasználó leltárában lévő tárgyak listáját.</returns>
        /// <response code="200">Visszaadja a felhasználó leltárában lévő tárgyak listáját.</response>
        /// <response code="401">A felhasználó nincs bejelentkezve, vagy a munkamenete lejárt.</response>
        [HttpGet]
        [ProducesResponseType(typeof(List<ItemResponse>), StatusCodes.Status200OK)]
        [ProducesResponseType(typeof(void), StatusCodes.Status401Unauthorized)]
        [Consumes("application/json")]
        [Produces("application/json")]
        [Route("inventory")]
        [Authorize]
        public ActionResult<List<ItemResponse>> Inventory()
        {
            User user = context.Users.First(x => x.Username == User.Identity!.Name);

            List<ItemResponse> items = context.Userinventories.Where(x => x.UserId == user.UserId).Select(x => x.Item!.ToDto()).ToList()!;

            return Ok(items);
        }

        /// <summary>
        /// Új access-refresh token pár generálása a felhasználó jelenlegi refresh tokene alapján.
        /// </summary>
        /// <returns>Egy új access-refresh token párt. Az access token-t a törzsben adja vissza, a refresh token-t meg sütiként.</returns>
        /// <response code="200">Visszaad egy új access-refresh token párt.</response>
        /// <response code="401">A felhasználó nincs bejelentkezve, vagy a munkamenete lejárt.</response>
        [HttpGet]
        [ProducesResponseType(typeof(ActionStatus), StatusCodes.Status200OK)]
        [ProducesResponseType(typeof(void), StatusCodes.Status401Unauthorized)]
        [Consumes("application/json")]
        [Produces("application/json")]
        [Route("refresh-token")]
        public ActionResult<ActionStatus> RefreshToken()
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

            return Ok(new ActionStatus{ Status = "OK", Message = accessToken });
        }

        /// <summary>
        /// Egy meglévő felhasználó bejelentkeztetése.
        /// </summary>
        /// <param name="login">Egy "Login" rekord, ami a felhasználó nevét, és jelszavát tartalmazza, és ha be van kapcsolva, akkor a két faktoros belépés adatait is.</param>
        /// <returns>Egy új access-refresh token párt.</returns>
        /// <response code="200">Visszaad egy új access-refresh token párt.</response>
        /// <response code="401">A bejelentkezés során hiba történt, a hiba leírása a válaszban található.</response>
        [HttpPost]
        [ProducesResponseType(StatusCodes.Status200OK)]
        [ProducesResponseType(typeof(void), StatusCodes.Status401Unauthorized)]
        [Consumes("application/json")]
        [Produces("application/json")]
        [Route("login")]
        public ActionResult<ActionStatus> LoginUser(LoginRequest login)
        {
            var storedUser = context.Users.FirstOrDefault(u => u.Username == login.Username);

            if (storedUser == null)
            {
                return BadRequest(new ActionStatus{ Status = "ERR", Message = "InvalidCredential" });
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
            if (login.Mfa == null) return Unauthorized(new ActionStatus{ Status = "UI", Message = twoFactorScenario });
            switch (login.Mfa.MfaType)
            {
                case MfaType.Totp:
                {
                    if (!storedUser.TotpEnabled) return BadRequest(new ActionStatus{ Status = "ERR", Message = "InvalidMFAMethod" });
                    if (login.Mfa.TotpToken == null) return BadRequest(new ActionStatus{ Status = "ERR", Message = "InvalidTotp" });
                    var totp = new Totp(Base32Encoding.ToBytes(storedUser.TotpSecret));
                    bool verify = totp.VerifyTotp(login.Mfa.TotpToken, out _,
                        VerificationWindow.RfcSpecifiedNetworkDelay);
                    return verify ? CheckPassword(login.Password, storedUser) : BadRequest(new ActionStatus{ Status = "ERR", Message = "InvalidTotp" });
                }
                case MfaType.WebAuthn:
                {
                    if (!storedUser.WebauthnEnabled) return BadRequest(new ActionStatus{ Status = "ERR", Message = "InvalidMFAMethod" });
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
                    return BadRequest(new ActionStatus{ Status = "ERR", Message = "InvalidCredential" });
                }
            }
        }

        /// <summary>
        /// Egy felhasználó admin jogainak ellenőrzése.
        /// </summary>
        /// <returns>204-es állapotkódot ha a felhasználó rendelkezik admin jogokkal, különben 403-as állapotkódot.</returns>
        /// <response code="204">A felhasználó rendelkezik admin jogokkal.</response>
        /// <response code="403">A felhasználó nem rendelkezik admin jogokkal.</response>
        /// <response code="401">A felhasználó nincs bejelentkezve, vagy a munkamenete lejárt.</response>
        [HttpGet]
        [Route("admin/check")]
        [ProducesResponseType(typeof(void), StatusCodes.Status204NoContent)]
        [ProducesResponseType(typeof(void), StatusCodes.Status403Forbidden)]
        [ProducesResponseType(typeof(void), StatusCodes.Status401Unauthorized)]
        [Consumes("application/json")]
        [Produces("application/json")]
        [Authorize]
        public ActionResult IsAdmin()
        {
            User user = context.Users.First(x => x.Username == User.Identity!.Name);
            return user.IsAdmin ? NoContent() : Forbid();
        }

        /// <summary>
        /// Az összes létező tárgy adatainak lekérdezése. (Admin jog szükséges)
        /// </summary>
        /// <returns>Egy listát, ami tartalmazza az összes tárgy adatait.</returns>
        /// <response code="200">Visszaad egy listát, ami tartalmazza az összes tárgy adatait.</response>
        /// <response code="403">A felhasználó nem rendelkezik admin jogokkal.</response>
        /// <response code="401">A felhasználó nincs bejelentkezve, vagy a munkamenete lejárt.</response>
        [HttpGet]
        [Route("admin/items")]
        [ProducesResponseType(typeof(List<ItemResponse>), StatusCodes.Status200OK)]
        [ProducesResponseType(typeof(void), StatusCodes.Status403Forbidden)]
        [ProducesResponseType(typeof(void), StatusCodes.Status401Unauthorized)]
        [Consumes("application/json")]
        [Produces("application/json")]
        [Authorize]
        public ActionResult<List<ItemResponse>> GetItems()
        {
            User user = context.Users.First(x => x.Username == User.Identity!.Name);
            if (!user.IsAdmin) return Forbid();

            return Ok(context.Items.Where(x => x.ItemType == ItemType.Item).Select(x => x.ToDto()).ToList());
        }

        /// <summary>
        /// Az összes létező felhasználó adatainak lekérdezése. (Admin jog szükséges)
        /// </summary>
        /// <returns>Egy listát, ami tartalmazza az összes felhasználó adatait.</returns>
        /// <response code="200">Visszaad egy listát, ami tartalmazza az összes felhasználó adatait.</response>
        /// <response code="403">A felhasználó nem rendelkezik admin jogokkal.</response>
        /// <response code="401">A felhasználó nincs bejelentkezve, vagy a munkamenete lejárt.</response>
        [HttpGet]
        [Route("admin/users")]
        [ProducesResponseType(typeof(List<UserResponse>), StatusCodes.Status200OK)]
        [ProducesResponseType(typeof(void), StatusCodes.Status403Forbidden)]
        [ProducesResponseType(typeof(void), StatusCodes.Status401Unauthorized)]
        [Consumes("application/json")]
        [Produces("application/json")]
        [Authorize]
        public ActionResult<List<UserResponse>> GetUsers()
        {
            User user = context.Users.First(x => x.Username == User.Identity!.Name);
            if (!user.IsAdmin) return Forbid();

            return Ok(context.Users.Select(x => x.ToDto(
                context.Userinventories.Where(y => y.UserId == x.UserId)
                    .Select(z => z.Item!.ToDto()).ToList()!)).ToList());
        }

        /// <summary>
        /// Új tárgy létrehozása. (Admin jog szükséges)
        /// </summary>
        /// <param name="details">A tárgy leírása.</param>
        /// <returns>A tárgy leírását.</returns>
        /// <response code="200">Visszaadja a tárgy leírását.</response>
        /// <response code="403">A felhasználó nem rendelkezik admin jogokkal.</response>
        /// <response code="401">A felhasználó nincs bejelentkezve, vagy a munkamenete lejárt.</response>
        [HttpPost]
        [Route("admin/items")]
        [ProducesResponseType(typeof(ItemResponse), StatusCodes.Status200OK)]
        [ProducesResponseType(typeof(void), StatusCodes.Status403Forbidden)]
        [ProducesResponseType(typeof(void), StatusCodes.Status401Unauthorized)]
        [Consumes("application/json")]
        [Produces("application/json")]
        [Authorize]
        public ActionResult<ItemResponse> AddItem(ItemRecord details)
        {
            User user = context.Users.First(x => x.Username == User.Identity!.Name);
            if (!user.IsAdmin) return Forbid();


            Item item = new()
            {
                ItemName = details.Name,
                ItemDescription = details.Description,
                ItemValue = details.Value,
                ItemRarity = details.Rarity,
                ItemSkinId = details.SkinId
            };
            context.Items.Add(item);
            context.SaveChanges();

            return Ok(item.ToDto());
        }

        /// <summary>
        /// Az összes létező skin adatainak lekérdezése. (Admin jog szükséges)
        /// </summary>
        /// <returns>Egy listát, ami tartalmazza az összes skin adatait.</returns>
        /// <response code="200">Visszaad egy listát, ami tartalmazza az összes skin adatait.</response>
        /// <response code="403">A felhasználó nem rendelkezik admin jogokkal.</response>
        /// <response code="401">A felhasználó nincs bejelentkezve, vagy a munkamenete lejárt.</response>
        [HttpGet]
        [Route("admin/skins")]
        [ProducesResponseType(typeof(List<SkinResponse>), StatusCodes.Status200OK)]
        [ProducesResponseType(typeof(void), StatusCodes.Status403Forbidden)]
        [ProducesResponseType(typeof(void), StatusCodes.Status401Unauthorized)]
        [Consumes("application/json")]
        [Produces("application/json")]
        [Authorize]
        public ActionResult<List<SkinResponse>> GetSkins()
        {
            User user = context.Users.First(x => x.Username == User.Identity!.Name);
            if (!user.IsAdmin) return Forbid();

            return Ok(context.Skins.Select(x => x.ToDto()).ToList());
        }

        /// <summary>
        /// Új skin létrehozása. (Admin jog szükséges)
        /// </summary>
        /// <param name="details">A skin leírása.</param>
        /// <returns>A skin leírását.</returns>
        /// <response code="200">Visszaadja a skin leírását.</response>
        /// <response code="403">A felhasználó nem rendelkezik admin jogokkal.</response>
        /// <response code="401">A felhasználó nincs bejelentkezve, vagy a munkamenete lejárt.</response>
        [HttpPost]
        [Route("admin/skins")]
        [ProducesResponseType(typeof(SkinResponse), StatusCodes.Status200OK)]
        [ProducesResponseType(typeof(void), StatusCodes.Status403Forbidden)]
        [ProducesResponseType(typeof(void), StatusCodes.Status401Unauthorized)]
        [Consumes("application/json")]
        [Produces("application/json")]
        [Authorize]
        public ActionResult<SkinResponse> AddSkin(SkinRecord details)
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

            return Ok(skin.ToDto());
        }

        /// <summary>
        /// Az összes létező láda adatainak lekérdezése.
        /// </summary>
        /// <returns>Egy listát, ami tartalmazza az összes láda adatait.</returns>
        /// <response code="200">Visszaad egy listát, ami tartalmazza az összes láda adatait.</response>
        /// <response code="401">A felhasználó nincs bejelentkezve, vagy a munkamenete lejárt.</response>
        [HttpGet]
        [Route("cases")]
        [ProducesResponseType(typeof(List<CaseResponse>), StatusCodes.Status200OK)]
        [ProducesResponseType(typeof(void), StatusCodes.Status401Unauthorized)]
        [Consumes("application/json")]
        [Produces("application/json")]
        [Authorize]
        public ActionResult<List<CaseResponse>> GetCases()
        {

            return Ok(context.Items.Where(x => x.ItemType == ItemType.Case).Select(
                x => x.ToCaseDto(
                    context.CaseItems
                        .Where(y => y.CaseId == x.ItemId)
                        .Select(z => z.Item!.ToDto()).ToList())).ToList());
        }

        /// <summary>
        /// Egy láda kinyitása.
        /// </summary>
        /// <param name="caseId">A láda azonosítója.</param>
        /// <returns>A megszerzett tárgy adatait.</returns>
        /// <response code="200">Visszaadja a megszerzett tárgy adatait.</response>
        /// <response code="404">A megadott láda nem létezik.</response>
        /// <response code="500">Hiba történt a kulcs keresése közben.</response>
        /// <response code="401">A felhasználó nincs bejelentkezve, vagy a munkamenete lejárt.</response>
        [HttpPost]
        [Route("open_case/{caseId}")]
        [ProducesResponseType(typeof(ItemResponse), StatusCodes.Status200OK)]
        [ProducesResponseType(typeof(void), StatusCodes.Status404NotFound)]
        [ProducesResponseType(typeof(void), StatusCodes.Status500InternalServerError)]
        [ProducesResponseType(typeof(void), StatusCodes.Status401Unauthorized)]
        [Consumes("application/json")]
        [Produces("application/json")]
        [Authorize]
        public ActionResult<ItemResponse> OpenCase(int caseId)
        {
            User user = context.Users.First(x => x.Username == User.Identity!.Name);

            var @case = context.Items.FirstOrDefault(x => x.ItemType == ItemType.Case && x.ItemId == caseId);
            if(@case == null) return NotFound();

            var key = context.CaseKeys.FirstOrDefault(x => x.CaseId == @case.ItemId);
            if (key == null) return StatusCode(StatusCodes.Status500InternalServerError);

            var userInventory = context.Userinventories.Where(x => x.UserId == user.UserId).Include(x => x.Item).ToList();

            var userCase = userInventory.Find(x => x.Item! == @case);
            var userCaseKey = userInventory.Find(x => x.ItemId == key.CaseKeyId);

            if (userCase == null || userCaseKey == null) return Forbid();
            {
                var caseItems = context.CaseItems.Where(x => x.Case == @case).ToArray();
                // Egyenlőre Random.Shared-et használunk itt, de később valami százalékos esély algoritmust kell ide raknunk.
                var resultItem = Random.Shared.GetItems(caseItems, 1)[0];

                context.Userinventories.Remove(userCase);
                context.Userinventories.Remove(userCaseKey);
                context.Userinventories.Add(new Userinventory
                {
                    InventoryId = userInventory.First().InventoryId,
                    ItemId = resultItem.ItemId,
                    ItemUpgradedAmount = 0,
                    UserId = user.UserId
                });
                context.SaveChanges();

                return Ok(resultItem);
            }

        }

        /// <summary>
        /// A közelgő nyereményjátékok adatainak lekérése.
        /// </summary>
        /// <returns>A közelgő nyereményjátékok adatait.</returns>
        /// <response code="200">Visszaad egy listát, ami tartalmazza a közelgő nyereményjátékok adatait.</response>
        /// <response code="401">A felhasználó nincs bejelentkezve, vagy a munkamenete lejárt.</response>
        [HttpGet]
        [Route("giveaways/current")]
        [ProducesResponseType(typeof(List<CurrentGiveawayResponse>), StatusCodes.Status200OK)]
        [ProducesResponseType(typeof(void), StatusCodes.Status401Unauthorized)]
        [Consumes("application/json")]
        [Produces("application/json")]
        [Authorize]
        public async Task<ActionResult<List<CurrentGiveawayResponse>>> GetGiveaways()
        {
            // Nyereményjátékok, amelyek még nem futottak le.
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

        /// <summary>
        /// A múltbeli nyereményjátékok adatainak lekérése.
        /// </summary>
        /// <returns>A múltbeli nyereményjátékok adatait.</returns>
        /// <response code="200">Visszaad egy listát, ami tartalmazza a múltbeli nyereményjátékok adatait.</response>
        /// <response code="401">A felhasználó nincs bejelentkezve, vagy a munkamenete lejárt.</response>
        [HttpGet]
        [Route("giveaways/past")]
        [Consumes("application/json")]
        [Produces("application/json")]
        [ProducesResponseType(typeof(List<PastGiveawayResponse>), StatusCodes.Status200OK)]
        [ProducesResponseType(typeof(void), StatusCodes.Status401Unauthorized)]
        [Authorize]
        public async Task<ActionResult<List<PastGiveawayResponse>>> GetPastGiveaways()
        {
            // Nyereményjátékok amelyek már lefutottak, és van nyertesük.
            var giveaways = await context.Giveaways
                .Where(x => x.GiveawayDate <= DateOnly.FromDateTime(DateTime.Now) && x.WinnerUserId != null)
                .Include(x => x.Item).Include(giveaway => giveaway.WinnerUser).ToListAsync();
            
            var mapped = giveaways.Select(giveaway => new PastGiveawayResponse
            {
                GiveawayDescription = giveaway.GiveawayDescription,
                GiveawayItem = giveaway.Item?.ItemName,
                GiveawayName = giveaway.GiveawayName,
                GiveawayId = giveaway.GiveawayId,
                WinnerName = giveaway.WinnerUser?.Username
            }).ToList();

            return Ok(mapped);
        }

        /// <summary>
        /// Új láda létrehozása. (Admin jog szükséges)
        /// </summary>
        /// <param name="details">A láda leírása.</param>
        /// <returns>A láda leírását.</returns>
        /// <response code="200">Visszaadja a láda leírását.</response>
        /// <response code="403">A felhasználó nem rendelkezik admin jogokkal.</response>
        /// <response code="401">A felhasználó nincs bejelentkezve, vagy a munkamenete lejárt.</response>
        [HttpPost]
        [Route("admin/cases")]
        [Consumes("application/json")]
        [Produces("application/json")]
        [ProducesResponseType(typeof(CaseResponse), StatusCodes.Status200OK)]
        [ProducesResponseType(typeof(void), StatusCodes.Status403Forbidden)]
        [ProducesResponseType(typeof(void), StatusCodes.Status401Unauthorized)]
        [Authorize]
        public ActionResult AddCase(CaseRecord details)
        {
            User user = context.Users.First(x => x.Username == User.Identity!.Name);
            if (!user.IsAdmin) return Forbid();


            Item @case = new()
            {
                ItemName = details.Name,
                ItemType = ItemType.Case,
                ItemSkinId = null
            };
            context.Items.Add(@case);
            context.SaveChanges();

            return Ok(@case);
        }

        /// <summary>
        /// Hozzáad egy tárgyat egy ládához. (Admin jog szükséges)
        /// </summary>
        /// <param name="caseId">A módosítandó láda azonosítója.</param>
        /// <param name="itemId">A hozzáadandó tárgy azonosítója.</param>
        /// <returns>A láda frissített adatait.</returns>
        /// <response code="200">Visszaadja a láda frissített adatait.</response>
        /// <response code="403">A felhasználó nem rendelkezik admin jogokkal.</response>
        /// <response code="401">A felhasználó nincs bejelentkezve, vagy a munkamenete lejárt.</response>
        [HttpPost]
        [Route("admin/cases/{caseId:int}/items/{itemId:int}")]
        [Consumes("application/json")]
        [Produces("application/json")]
        [ProducesResponseType(typeof(CaseResponse), StatusCodes.Status200OK)]
        [ProducesResponseType(typeof(void), StatusCodes.Status403Forbidden)]
        [ProducesResponseType(typeof(void), StatusCodes.Status401Unauthorized)]
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

        /// <summary>
        /// Eltávolít egy tárgyat egy ládából. (Admin jog szükséges)
        /// </summary>
        /// <param name="caseId">A módosítandó láda azonosítója.</param>
        /// <param name="itemId">A eltávolítandó tárgy azonosítója.</param>
        /// <returns>A láda frissített adatait.</returns>
        /// <response code="200">Visszaadja a láda frissített adatait.</response>
        /// <response code="403">A felhasználó nem rendelkezik admin jogokkal.</response>
        /// <response code="401">A felhasználó nincs bejelentkezve, vagy a munkamenete lejárt.</response>
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

            // Access token létrehozása
            var accessToken = new JwtSecurityToken(
                issuer: Globals.Config.BackUrl,
                audience: Globals.Config.BackUrl,
                claims: claims,
                expires: DateTime.Now.AddMinutes(30),
                signingCredentials: Signing.AccessTokenCreds);
            var accessTokenString = new JwtSecurityTokenHandler().WriteToken(accessToken);

            // Refresh token létrehozása
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
            return Ok(new ActionStatus{ Status = "OK", Message = accessToken });

        }
    }
}
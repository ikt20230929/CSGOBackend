using System.IdentityModel.Tokens.Jwt;
using System.Text;
using csgo.Models;
using csgo.Services;
using Fido2NetLib;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using static csgo.Dtos;

namespace csgo.Controllers
{
    /// <summary>
    /// Backend végpontok.
    /// </summary>
    /// <param name="service">A backend szolgáltatás</param>
    [ApiController]
    [Route("api")]
    public class CsgoBackendController(ICsgoBackendService service) : ControllerBase
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
        public async Task<ActionResult<ActionStatus>> Register(RegisterRequest register)
        {
            var response = await service.RegisterAsync(register);
            return response.Status == "OK" ? Ok(response) : BadRequest(response);
        }

        /// <summary>
        /// A jelenleg bejelentkezett felhasználó profil adatainak lekérése.
        /// </summary>
        /// <returns>A jelenleg bejelentkezett felhasználónevét, és a jelenlegi egyenlegét.</returns>
        /// <response code="200">Visszaadja a jelenleg bejelentkezett felhasználónevét, és a jelenlegi egyenlegét.</response>
        /// <response code="401">A felhasználó nincs bejelentkezve, vagy a munkamenete lejárt.</response>
        [HttpGet]
        [ProducesResponseType(typeof(UserResponse), StatusCodes.Status200OK)]
        [ProducesResponseType(typeof(void), StatusCodes.Status401Unauthorized)]
        [Consumes("application/json")]
        [Produces("application/json")]
        [Route("profile")]
        [Authorize]
        public async Task<ActionResult<ActionStatus>> Profile()
        {
            User user = (await service.GetUserAsync(User.Identity!.Name!)).Message!;
            var response = await service.GetProfileAsync(user);
            
            return Ok(response);
        }

        /// <summary>
        /// Felhasználó beazonosítása refresh token alapján.
        /// </summary>
        /// <param name="token">A refresh token.</param>
        /// <returns>A tokenhez tartozó felhasználót.</returns>
        private async Task<User> GetUserFromRefreshJwt(string token)
        {

            var tokenHandler = new JwtSecurityTokenHandler();
            var jwtToken = tokenHandler.ReadJwtToken(token);
            jwtToken!.Payload.TryGetValue("name", out var username);
            var response = await service.GetUserAsync((string)username!);
            return response.Message!;
        }

        /// <summary>
        /// A jelenleg bejelentkezett felhasználó leltárában lévő tárgyak lekérése.
        /// </summary>
        /// <returns>A jelenleg bejelentkezett felhasználó leltárában lévő tárgyak listáját.</returns>
        /// <response code="200">Visszaadja A jelenleg bejelentkezett felhasználó leltárában lévő tárgyak listáját.</response>
        /// <response code="401">A felhasználó nincs bejelentkezve, vagy a munkamenete lejárt.</response>
        [HttpGet]
        [ProducesResponseType(typeof(List<InventoryItemResponse>), StatusCodes.Status200OK)]
        [ProducesResponseType(typeof(void), StatusCodes.Status401Unauthorized)]
        [Consumes("application/json")]
        [Produces("application/json")]
        [Route("inventory")]
        [Authorize]
        public async Task<ActionResult<List<InventoryItemResponse>>> Inventory()
        {
            User user = (await service.GetUserAsync(User.Identity!.Name!)).Message!;
            var response = await service.GetInventoryAsync(user);

            return Ok(response);
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
        public async Task<ActionResult<ActionStatus>> RefreshToken()
        {
            var currentRefreshToken = HttpContext.Request.Cookies["refreshToken"];
            if (currentRefreshToken == null) return Unauthorized();
            User user = await GetUserFromRefreshJwt(currentRefreshToken);
            var (accessToken, refreshToken) = service.GenerateTokens(user);

            Response.Cookies.Append("refreshToken", refreshToken, new CookieOptions
            {
                HttpOnly = true,
                SameSite = SameSiteMode.None,
                MaxAge = TimeSpan.FromDays(7),
                Secure = true
            });

            return Ok(new ActionStatus { Status = "OK", Message = accessToken });
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
        public async Task<ActionResult<ActionStatus>> LoginUser(LoginRequest login)
        {
            ActionStatus loginRequest;

            if(HttpContext.Session.GetString("fido2.attestationOptions") != null)
            {
                loginRequest = await service.LoginUserAsync(login, HttpContext.Session.GetString("fido2.attestationOptions"));
            }else{
                loginRequest = await service.LoginUserAsync(login);
            }

            switch (loginRequest.Status)
            {
                case "OK": {
                    Response.Cookies.Append("refreshToken", loginRequest.Message!.Item2, new CookieOptions
                    {
                        HttpOnly = true,
                        SameSite = SameSiteMode.None,
                        MaxAge = TimeSpan.FromDays(7),
                        Secure = true
                    });

                    return Ok(new ActionStatus { Status = "OK", Message = loginRequest.Message!.Item1 });
                }
                
                case "UI": {
                    if(login.Mfa!.MfaType == MfaType.WebAuthnOptions) {
                        HttpContext.Session.SetString("fido2.attestationOptions", loginRequest.Message!);
                    }

                    return Unauthorized(loginRequest);
                }

                case "ERR": {
                    return Unauthorized(loginRequest);
                }
            }

            // Ennek sosem kéne megtörténnie
            return StatusCode(500);
        }

        /// <summary>
        /// WebAuthn attesztáció (1. lépés).
        /// </summary>
        /// <returns>A WebAuthn attesztáció beállításait.</returns>
        /// <response code="200">Visszaadja a WebAuthn attesztáció beállításait.</response>
        /// <response code="401">A felhasználó nincs bejelentkezve, vagy a munkamenete lejárt.</response>
        [HttpGet]
        [Authorize]
        [Route("webauthn")]
        [ProducesResponseType(typeof(CredentialCreateOptions), StatusCodes.Status200OK)]
        [ProducesResponseType(typeof(void), StatusCodes.Status401Unauthorized)]
        [Consumes("application/json")]
        [Produces("application/json")]
        public async Task<ActionResult> WebAuthnAttestation(WebauthnAttestationRequest request)
        {
            User user = (await service.GetUserAsync(User.Identity!.Name!)).Message!;

            throw new NotImplementedException();
        }

        /// <summary>
        /// TOTP kulcs generálása
        /// </summary>
        /// <returns>Egy TOTP kulcsot</returns>
        /// <response code="200">Visszaad egy TOTP kulcsot</response>
        /// <response code="401">A felhasználó nincs bejelentkezve, vagy a munkamenete lejárt.</response>
        /// <response code="409">A TOTP kulcs generálása nem történt meg, mivel a felhasználó már engedélyezte a TOTP alapú 2FA-t</response>
        [HttpGet]
        [Route("totp")]
        [ProducesResponseType(typeof(ActionStatus), StatusCodes.Status200OK)]
        [ProducesResponseType(typeof(void), StatusCodes.Status401Unauthorized)]
        [ProducesResponseType(typeof(void), StatusCodes.Status409Conflict)]
        [Produces("application/json")]
        [Authorize]
        public async Task<ActionResult<ActionStatus>> GenerateTotpToken()
        {
            User user = (await service.GetUserAsync(User.Identity!.Name!)).Message!;
            var response = await service.GenerateTotpTokenAsync(user);

            return response.Status == "OK" ? Ok(response) : Conflict(response);
        }

        /// <summary>
        /// TOTP kulcs ellenőrzeése
        /// </summary>
        /// <param name="request">A TOTP kulcs</param>
        /// <returns>204 ha sikerült, 403 ha nem.</returns>
        /// <response code="204">A TOTP kulcs ellenőrzés sikeres volt.</response>
        /// <response code="403">A TOTP kulcs ellenőrzés sikertelen volt.</response>
        /// <response code="401">A felhasználó nincs bejelentkezve, vagy a munkamenete lejárt.</response>
        /// <response code="409">Ez a végpont csak a 2FA beállítása közben használható.</response>
        [HttpPost]
        [Route("totp")]
        [ProducesResponseType(typeof(void), StatusCodes.Status204NoContent)]
        [ProducesResponseType(typeof(void), StatusCodes.Status403Forbidden)]
        [ProducesResponseType(typeof(void), StatusCodes.Status401Unauthorized)]
        [ProducesResponseType(typeof(void), StatusCodes.Status409Conflict)]
        [Produces("application/json")]
        [Consumes("application/json")]
        [Authorize]
        public async Task<ActionResult<ActionStatus>> CheckTotpToken(EnableTOTPRequest request)
        {
            User user = (await service.GetUserAsync(User.Identity!.Name!)).Message!;
            var response = await service.CheckTotpTokenAsync(user, request);

            return response.Status == "OK" ? NoContent() : Forbid();
        }

        /// <summary>
        /// TOTP kikapcsolása
        /// </summary>
        /// <returns>204 ha sikerült, 403 ha nem.</returns>
        /// <response code="204">A TOTP kikapcsolása sikeres volt.</response>
        /// <response code="403">Érvénytelen TOTP azonosító vagy jelszó.</response>
        /// <response code="401">A felhasználó nincs bejelentkezve, vagy a munkamenete lejárt.</response>
        /// <response code="409">A felhasználónak nincs bekapcsolva a TOTP.</response>
        /// <param name="request">TOTP kód, jelszó</param>
        [HttpDelete]
        [Route("totp")]
        [ProducesResponseType(typeof(void), StatusCodes.Status204NoContent)]
        [ProducesResponseType(typeof(void), StatusCodes.Status403Forbidden)]
        [ProducesResponseType(typeof(void), StatusCodes.Status401Unauthorized)]
        [ProducesResponseType(typeof(void), StatusCodes.Status409Conflict)]
        [Consumes("application/json")]
        [Authorize]
        public async Task<ActionResult<ActionStatus>> DisableTotp(DisableTOTPRequest request)
        {
            User user = (await service.GetUserAsync(User.Identity!.Name!)).Message!;
            var response = await service.DisableTotpAsync(user, request);

            return response.Status == "OK" ? NoContent() : Forbid();
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
        public async Task<ActionResult<List<CaseResponse>>> GetCases()
        {
            return await service.GetCasesAsync();
        }

        /// <summary>
        /// Egy láda kinyitása.
        /// </summary>
        /// <param name="caseId">A láda azonosítója.</param>
        /// <returns>A megszerzett tárgy adatait.</returns>
        /// <response code="200">Visszaadja a megszerzett tárgy adatait.</response>
        /// <response code="404">A megadott láda nem létezik.</response>
        /// <response code="403">A jelenleg bejelentkezett felhasználónak nincs elég egyenlege a láda kinyitásához.</response>
        /// <response code="401">A felhasználó nincs bejelentkezve, vagy a munkamenete lejárt.</response>
        [HttpPost]
        [Route("open_case/{caseId}")]
        [ProducesResponseType(typeof(ItemResponse), StatusCodes.Status200OK)]
        [ProducesResponseType(typeof(void), StatusCodes.Status404NotFound)]
        [ProducesResponseType(typeof(void), StatusCodes.Status403Forbidden)]
        [ProducesResponseType(typeof(void), StatusCodes.Status401Unauthorized)]
        [Consumes("application/json")]
        [Produces("application/json")]
        [Authorize]
        public async Task<ActionResult<ItemResponse>> OpenCase(int caseId)
        {
            User user = (await service.GetUserAsync(User.Identity!.Name!)).Message!;
            var response = await service.OpenCaseAsync(user, caseId);

            return response.Status == "OK" ? Ok(response) : response.Status == "ERR" ? NotFound() : Forbid();
        }

        /// <summary>
        /// Az összes létező tárgy adatainak lekérdezése.
        /// </summary>
        /// <returns>Egy listát, ami tartalmazza az összes tárgy adatait.</returns>
        /// <response code="200">Visszaad egy listát, ami tartalmazza az összes tárgy adatait.</response>
        /// <response code="401">A felhasználó nincs bejelentkezve, vagy a munkamenete lejárt.</response>
        [HttpGet]
        [Route("items")]
        [ProducesResponseType(typeof(List<ItemResponse>), StatusCodes.Status200OK)]
        [ProducesResponseType(typeof(void), StatusCodes.Status401Unauthorized)]
        [Consumes("application/json")]
        [Produces("application/json")]
        [Authorize]
        public async Task<ActionResult<List<ItemResponse>>> GetItems()
        {
            return await service.GetItemsAsync();
        }

        /// <summary>
        /// Egy tárgy eladása.
        /// </summary>
        /// <param name="inventoryId">A tárgy leltárazonosítója.</param>
        /// <returns>204 ha sikerült, 404 ha nem található.</returns>
        /// <response code="204">A tárgy eladása sikeres volt.</response>
        /// <response code="404">A megadott tárgy nem található.</response>
        /// <response code="401">A felhasználó nincs bejelentkezve, vagy a munkamenete lejárt.</response>
        [HttpPost]
        [Route("sell_item/{inventoryId:int}")]
        [ProducesResponseType(typeof(void), StatusCodes.Status204NoContent)]
        [ProducesResponseType(typeof(void), StatusCodes.Status404NotFound)]
        [ProducesResponseType(typeof(void), StatusCodes.Status401Unauthorized)]
        [Produces("application/json")]
        [Authorize]
        public async Task<ActionResult<ActionStatus>> SellItem(int inventoryId)
        {
            User user = (await service.GetUserAsync(User.Identity!.Name!)).Message!;
            var response = await service.SellItemAsync(user, inventoryId);

            return response.Status == "OK" ? NoContent() : NotFound();
        }

        /// <summary>
        /// Egy vagy több tárgy kikérése.
        /// </summary>
        /// <param name="request">A tárgyak leltárazonosítói.</param>
        /// <returns>204 ha sikerült, 400 ha nem.</returns>
        /// <response code="204">A tárgyak kikérése sikeres volt.</response>
        /// <response code="404">A tárgy nem található.</response>
        /// <response code="401">A felhasználó nincs bejelentkezve, vagy a munkamenete lejárt.</response>
        [HttpPost]
        [Route("items/withdraw")]
        [ProducesResponseType(typeof(void), StatusCodes.Status204NoContent)]
        [ProducesResponseType(typeof(void), StatusCodes.Status404NotFound)]
        [ProducesResponseType(typeof(void), StatusCodes.Status401Unauthorized)]
        [Produces("application/json")]
        [Consumes("application/json")]
        [Authorize]
        public async Task<ActionResult<ActionStatus>> WithdrawItems(ItemWithdrawRequest request)
        {
            User user = (await service.GetUserAsync(User.Identity!.Name!)).Message!;
            var response = await service.WithdrawItemsAsync(user, request);

            return response.Status == "OK" ? NoContent() : NotFound();
        }

        /// <summary>
        /// Egyenleg feltöltése.
        /// </summary>
        /// <param name="amount">A feltöltendő összeg.</param> 
        /// <returns>204 ha sikerült, 400 ha nem.</returns>
        /// <response code="204">A feltöltés sikeres volt.</response>
        /// <response code="400">A feltöltés sikertelen volt.</response>
        /// <response code="401">A felhasználó nincs bejelentkezve, vagy a munkamenete lejárt.</response>
        [HttpPost]
        [Route("deposit")]
        [ProducesResponseType(typeof(void), StatusCodes.Status204NoContent)]
        [ProducesResponseType(typeof(void), StatusCodes.Status400BadRequest)]
        [ProducesResponseType(typeof(void), StatusCodes.Status401Unauthorized)]
        [Produces("application/json")]
        [Consumes("application/json")]
        [Authorize]
        public async Task<ActionResult> Deposit(double amount)
        {
            User user = (await service.GetUserAsync(User.Identity!.Name!)).Message!;
            var response = await service.DepositAsync(user, amount);

            return response.Status == "OK" ? NoContent() : BadRequest();
        }


        /// <summary>
        /// Visszaad egy listát, ami azt tartalmazza hogy melyik tárgyakra lehet továbbfejleszteni a megadott tárgy(akat).
        /// </summary>
        /// <param name="request">A tárgy(ak) leltárazonosítójai, és a szorzó.</param>
        /// <returns>Egy listát, ami azt tartalmazza hogy melyik tárgyakra lehet továbbfejleszteni a megadott tárgyat.</returns>
        /// <response code="200">Visszaad egy listát, ami azt tartalmazza hogy melyik tárgyakra lehet továbbfejleszteni a megadott tárgyat.</response>
        /// <response code="404">Nem található a megadott tárgy.</response>
        /// <response code="401">A felhasználó nincs bejelentkezve, vagy a munkamenete lejárt.</response>
        /// <response code="409">A megadott tárgy nem fejleszthető tovább.</response>
        [HttpPost]
        [Route("items/upgrades")]
        [ProducesResponseType(typeof(ActionStatus), StatusCodes.Status200OK)]
        [ProducesResponseType(typeof(void), StatusCodes.Status404NotFound)]
        [ProducesResponseType(typeof(void), StatusCodes.Status401Unauthorized)]
        [ProducesResponseType(typeof(void), StatusCodes.Status409Conflict)]
        [Authorize]
        public async Task<ActionResult<ActionStatus>> GetUpgradeItems(ItemUpgradeListRequest request)
        {
            User user = (await service.GetUserAsync(User.Identity!.Name!)).Message!;
            var response = await service.GetUpgradeItemsAsync(request);

            return response.Status == "OK" ? Ok(response) : response.Status == "ERR" ? NotFound() : Conflict(response);
        }

        /// <summary>
        /// Egy tárgy továbbfejlesztése
        /// </summary>
        /// <param name="request">A tárgy(ak) leltárazonosítójai, a kért tárgy azonosítója, és a szorzó.</param>
        /// <returns>Visszaadja a fejleszett tárgya adatait ha sikerült, különben null.</returns>
        /// <response code="200">Visszaadja a fejlesztett tárgy adatait ha sikerült, különben null.</response>
        /// <response code="404">Nem találhato a megadott tárgy.</response>
        /// <response code="401">A felhasználó nincs bejelentkezve, vagy a munkamenete lejárt.</response>
        [HttpPost]
        [Route("items/upgrade")]
        [ProducesResponseType(typeof(ItemUpgradeResponse), StatusCodes.Status200OK)]
        [ProducesResponseType(typeof(void), StatusCodes.Status404NotFound)]
        [ProducesResponseType(typeof(void), StatusCodes.Status401Unauthorized)]
        [Authorize]
        public async Task<ActionResult<ItemUpgradeResponse>> UpgradeItem(ItemUpgradeRequest request)
        {
            User user = (await service.GetUserAsync(User.Identity!.Name!)).Message!;
            var response = await service.UpgradeItemAsync(user, request);

            return response.Status == "OK" ? Ok(response) : NotFound();
        }

        /// <summary>
        /// Napi jutalom kiváltása.
        /// </summary>
        /// <returns>A napi jutalom mennyiségét.</returns>
        /// <response code="200">Visszaadja a napi jutalom mennyiségét.</response>
        /// <response code="409">A felhasználó már kiváltotta a napi jutalmat.</response>
        /// <response code="401">A felhasználó nincs bejelentkezve, vagy a munkamenete lejárt.</response>
        [HttpGet]
        [Route("daily")]
        [ProducesResponseType(typeof(void), StatusCodes.Status200OK)]
        [ProducesResponseType(typeof(void), StatusCodes.Status409Conflict)]
        [ProducesResponseType(typeof(void), StatusCodes.Status401Unauthorized)]
        [Consumes("application/json")]
        [Produces("application/json")]
        [Authorize]
        public async Task<ActionResult> ClaimDailyReward()
        {
            User user = (await service.GetUserAsync(User.Identity!.Name!)).Message!;
            var response = await service.ClaimDailyRewardAsync(user);

            return response.Status == "OK" ? Ok(response) : Conflict();
        }

        /// <summary>
        /// Csatlakozás egy jelenleg aktív nyereményjátékhoz.
        /// </summary>
        /// <param name="id">A csatlakozandó nyereményjáték azonosítója.</param>
        /// <returns>204-es állapotkódot, ha a nyereményjátékhoz való csatlakozás sikeres volt, ha a felhasználó már csatlakozott, akkor a 409-es állapotkódot.</returns>
        /// <response code="204">Sikeres csatlakozás.</response>
        /// <response code="409">A nyereményjátékhoz már csatlakozott.</response>
        /// <response code="404">A megadott nyereményjáték nem létezik.</response>
        /// <response code="401">A felhasználó nincs bejelentkezve, vagy a munkamenete lejárt.</response>
        [HttpPost]
        [Route("giveaways/{id:int}")]
        [ProducesResponseType(typeof(void), StatusCodes.Status204NoContent)]
        [ProducesResponseType(typeof(void), StatusCodes.Status409Conflict)]
        [ProducesResponseType(typeof(void), StatusCodes.Status404NotFound)]
        [ProducesResponseType(typeof(void), StatusCodes.Status401Unauthorized)]
        [Consumes("application/json")]
        [Produces("application/json")]
        [Authorize]
        public async Task<ActionResult> JoinGiveaway(int id)
        {
            User user = (await service.GetUserAsync(User.Identity!.Name!)).Message!;
            var response = await service.JoinGiveawayAsync(user, id);

            return response.Status == "OK" ? NoContent() : response.Status == "ERR" ? NotFound() : Conflict();
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
            return await service.GetGiveawaysAsync();
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
            return await service.GetPastGiveawaysAsync();
        }

        /// <summary>
        /// Új láda létrehozása. (Admin jog szükséges)
        /// </summary>
        /// <param name="details">A láda leírása.</param>
        /// <returns>A láda leírását.</returns>
        /// <response code="200">Visszaadja a láda leírását.</response>
        /// <response code="403">A jelenleg bejelentkezett felhasználó nem rendelkezik admin jogokkal</response>
        /// <response code="401">A felhasználó nincs bejelentkezve, vagy a munkamenete lejárt.</response>
        [HttpPost]
        [Route("admin/cases")]
        [Consumes("application/json")]
        [Produces("application/json")]
        [ProducesResponseType(typeof(CaseResponse), StatusCodes.Status200OK)]
        [ProducesResponseType(typeof(void), StatusCodes.Status403Forbidden)]
        [ProducesResponseType(typeof(void), StatusCodes.Status401Unauthorized)]
        [Authorize]
        public async Task<ActionResult> AddCase(CaseRecord details)
        {
            User user = (await service.GetUserAsync(User.Identity!.Name!)).Message!;
            if (!user.IsAdmin) return Forbid();

            var @case = await service.AddCaseAsync(details);
            return Ok(@case);
        }

        /// <summary>
        /// Létező láda törlése (Admin jog szükséges)
        /// </summary>
        /// <param name="caseId">A láda azonosítója.</param>
        /// <returns>204 ha sikerült, 404 ha nem található.</returns>
        /// <response code="204">A törlés sikeres volt.</response>
        /// <response code="404">A láda nem található.</response>
        /// <response code="401">A felhasználó nincs bejelentkezve, vagy a munkamenete lejárt.</response>
        /// <response code="403">A jelenleg bejelentkezett felhasználó nem rendelkezik admin jogokkal</response>
        [HttpDelete]
        [Route("admin/cases/{caseId:int}")]
        [Consumes("application/json")]
        [ProducesResponseType(typeof(void), StatusCodes.Status204NoContent)]
        [ProducesResponseType(typeof(void), StatusCodes.Status404NotFound)]
        [ProducesResponseType(typeof(void), StatusCodes.Status401Unauthorized)]
        [ProducesResponseType(typeof(void), StatusCodes.Status403Forbidden)]
        [Authorize]
        public async Task<ActionResult> DeleteCase(int caseId)
        {
            User user = (await service.GetUserAsync(User.Identity!.Name!)).Message!;
            if (!user.IsAdmin) return Forbid();

            var response = await service.DeleteCaseAsync(caseId);
            return response.Status == "OK" ? NoContent() : NotFound();
        }

        /// <summary>
        /// Létező láda módosítása (Admin jog szükséges)
        /// </summary>
        /// <param name="caseId">A módosítandó láda azonosítója.</param>
        /// <param name="details">A láda új adatai.</param>
        /// <returns>A láda frissített adatait.</returns>
        /// <response code="200">Visszaadja a láda frissített adatait.</response>
        /// <response code="404">A láda nem található.</response>
        /// <response code="403">A jelenleg bejelentkezett felhasználó nem rendelkezik admin jogokkal</response>
        /// <response code="401">A felhasználó nincs bejelentkezve, vagy a munkamenete lejárt.</response>
        [HttpPut]
        [Route("admin/cases/{caseId:int}")]
        [Consumes("application/json")]
        [Produces("application/json")]
        [ProducesResponseType(typeof(CaseResponse), StatusCodes.Status200OK)]
        [ProducesResponseType(typeof(void), StatusCodes.Status404NotFound)]
        [ProducesResponseType(typeof(void), StatusCodes.Status403Forbidden)]
        [ProducesResponseType(typeof(void), StatusCodes.Status401Unauthorized)]
        [Authorize]
        public async Task<ActionResult> UpdateCase(int caseId, CaseRecord details)
        {
            User user = (await service.GetUserAsync(User.Identity!.Name!)).Message!;
            if (!user.IsAdmin) return Forbid();

            var response = await service.UpdateCaseAsync(caseId, details);

            return response.Status == "OK" ? Ok(response) : NotFound();
        }

        /// <summary>
        /// Hozzáad egy tárgyat egy ládához. (Admin jog szükséges)
        /// </summary>
        /// <param name="caseId">A módosítandó láda azonosítója.</param>
        /// <param name="itemId">A hozzáadandó tárgy azonosítója.</param>
        /// <returns>A láda frissített adatait.</returns>
        /// <response code="200">Visszaadja a láda frissített adatait.</response>
        /// <response code="403">A jelenleg bejelentkezett felhasználó nem rendelkezik admin jogokkal</response>
        /// <response code="404">A láda vagy tárgy nem található.</response>
        /// <response code="401">A felhasználó nincs bejelentkezve, vagy a munkamenete lejárt.</response>
        [HttpPost]
        [Route("admin/cases/{caseId:int}/items/{itemId:int}")]
        [Consumes("application/json")]
        [Produces("application/json")]
        [ProducesResponseType(typeof(CaseResponse), StatusCodes.Status200OK)]
        [ProducesResponseType(typeof(void), StatusCodes.Status403Forbidden)]
        [ProducesResponseType(typeof(void), StatusCodes.Status404NotFound)]
        [ProducesResponseType(typeof(void), StatusCodes.Status401Unauthorized)]
        [Authorize]
        public async Task<ActionResult> AddCaseItem(int caseId, int itemId)
        {
            User user = (await service.GetUserAsync(User.Identity!.Name!)).Message!;
            if (!user.IsAdmin) return Forbid();

            var response = await service.AddCaseItemAsync(caseId, itemId);
            return response.Status == "OK" ? Ok(response) : NotFound();
        }

        /// <summary>
        /// Eltávolít egy tárgyat egy ládából. (Admin jog szükséges)
        /// </summary>
        /// <param name="caseId">A módosítandó láda azonosítója.</param>
        /// <param name="itemId">A eltávolítandó tárgy azonosítója.</param>
        /// <returns>A láda frissített adatait.</returns>
        /// <response code="200">Visszaadja a láda frissített adatait.</response>
        /// <response code="403">A jelenleg bejelentkezett felhasználó nem rendelkezik admin jogokkal</response>
        /// <response code="404">A láda vagy tárgy nem található.</response>
        /// <response code="401">A felhasználó nincs bejelentkezve, vagy a munkamenete lejárt.</response>
        [HttpDelete]
        [Consumes("application/json")]
        [Produces("application/json")]
        [ProducesResponseType(typeof(CaseResponse), StatusCodes.Status200OK)]
        [ProducesResponseType(typeof(void), StatusCodes.Status403Forbidden)]
        [ProducesResponseType(typeof(void), StatusCodes.Status404NotFound)]
        [ProducesResponseType(typeof(void), StatusCodes.Status401Unauthorized)]
        [Route("admin/cases/{caseId:int}/items/{itemId:int}")]
        [Authorize]
        public async Task<ActionResult> DeleteCaseItem(int caseId, int itemId)
        {
            User user = (await service.GetUserAsync(User.Identity!.Name!)).Message!;
            if (!user.IsAdmin) return Forbid();

            var response = await service.DeleteCaseItemAsync(caseId, itemId);
            return response.Status == "OK" ? Ok(response) : NotFound();
        }

        /// <summary>
        /// Új nyereményjáték létrehozása. (Admin jog szükséges)
        /// </summary>
        /// <param name="details">A nyereményjáték leírása.</param>
        /// <returns>A nyereményjáték leírását.</returns>
        /// <response code="200">Visszaadja a nyereményjáték leírását.</response>
        /// <response code="403">A jelenleg bejelentkezett felhasználó nem rendelkezik admin jogokkal</response>
        /// <response code="401">A felhasználó nincs bejelentkezve, vagy a munkamenete lejárt.</response>
        /// <response code="404">A megadott tárgy nem található.</response>
        [HttpPost]
        [Route("admin/giveaways")]
        [Consumes("application/json")]
        [Produces("application/json")]
        [ProducesResponseType(typeof(CurrentGiveawayResponse), StatusCodes.Status200OK)]
        [ProducesResponseType(typeof(void), StatusCodes.Status403Forbidden)]
        [ProducesResponseType(typeof(void), StatusCodes.Status401Unauthorized)]
        [ProducesResponseType(typeof(void), StatusCodes.Status404NotFound)]
        [Authorize]
        public async Task<ActionResult<CurrentGiveawayResponse>> AddGiveaway(GiveawayRecord details)
        {
            User user = (await service.GetUserAsync(User.Identity!.Name!)).Message!;
            if (!user.IsAdmin) return Forbid();

            var response = await service.AddGiveawayAsync(details);

            return response.Status == "OK" ? Ok(response) : NotFound();
        }

        /// <summary>
        /// Létező nyeremenyjáték törlése (Admin jog szükséges)
        /// </summary>
        /// <param name="giveawayId">A nyereményjáték azonosítója.</param>
        /// <returns>204 ha sikerült, 404 ha nem található.</returns>
        /// <response code="204">Sikeres törlés.</response>
        /// <response code="403">A jelenleg bejelentkezett felhasználó nem rendelkezik admin jogokkal</response>
        /// <response code="401">A felhasználó nincs bejelentkezve, vagy a munkamenete lejárt.</response>
        /// <response code="404">A megadott nyereményjáték nem található.</response>
        [HttpDelete]
        [Route("admin/giveaways/{giveawayId:int}")]
        [Consumes("application/json")]
        [ProducesResponseType(typeof(void), StatusCodes.Status200OK)]
        [ProducesResponseType(typeof(void), StatusCodes.Status404NotFound)]
        [ProducesResponseType(typeof(void), StatusCodes.Status401Unauthorized)]
        [ProducesResponseType(typeof(void), StatusCodes.Status403Forbidden)]
        [Authorize]
        public async Task<ActionResult> DeleteGiveaway(int giveawayId)
        {
            User user = (await service.GetUserAsync(User.Identity!.Name!)).Message!;
            if (!user.IsAdmin) return Forbid();

            var response = await service.DeleteGiveawayAsync(giveawayId);
            return response.Status == "OK" ? NoContent() : NotFound();
        }

        /// <summary>
        /// Létező nyereményjáték adatainak módosítása. (Admin jog szükséges)
        /// </summary>
        /// <param name="giveawayId">A nyereményjáték azonosítója.</param>
        /// <param name="details">A nyereményjáték új adatai.</param>
        /// <returns>A nyereményjáték új adatait.</returns>
        /// <response code="200">Visszaadja a nyereményjáték új adatait.</response>
        /// <response code="403">A jelenleg bejelentkezett felhasználó nem rendelkezik admin jogokkal</response>
        /// <response code="404">A megadott nyereményjáték nem található.</response>
        /// <response code="401">A felhasználó nincs bejelentkezve, vagy a munkamenete lejárt.</response>
        /// <response code="409">A nyereményjáték már lefutott.</response>
        /// <response code="400">A megadott dátum nem lehet a multban.</response>
        [HttpPut]
        [Route("admin/giveaways/{giveawayId:int}")]
        [Consumes("application/json")]
        [Produces("application/json")]
        [ProducesResponseType(typeof(ActionStatus), StatusCodes.Status200OK)]
        [ProducesResponseType(typeof(void), StatusCodes.Status403Forbidden)]
        [ProducesResponseType(typeof(void), StatusCodes.Status404NotFound)]
        [ProducesResponseType(typeof(void), StatusCodes.Status401Unauthorized)]
        [ProducesResponseType(typeof(void), StatusCodes.Status409Conflict)]
        [ProducesResponseType(typeof(void), StatusCodes.Status400BadRequest)]
        [Authorize]
        public async Task<ActionResult<ActionStatus>> UpdateGiveaway(int giveawayId, GiveawayRecord details)
        {
            User user = (await service.GetUserAsync(User.Identity!.Name!)).Message!;
            if (!user.IsAdmin) return Forbid();

            var response = await service.UpdateGiveawayAsync(giveawayId, details);

            return response.Status == "OK" ? Ok(response) : response.Status == "ERR" ? NotFound() : Conflict(response);
        }

        /// <summary>
        /// Új tárgy létrehozása. (Admin jog szükséges)
        /// </summary>
        /// <param name="details">A tárgy leírása.</param>
        /// <returns>A tárgy leírását.</returns>
        /// <response code="200">Visszaadja a tárgy leírását.</response>
        /// <response code="403">A jelenleg bejelentkezett felhasználó nem rendelkezik admin jogokkal</response>
        /// <response code="401">A felhasználó nincs bejelentkezve, vagy a munkamenete lejárt.</response>
        [HttpPost]
        [Route("admin/items")]
        [ProducesResponseType(typeof(ItemResponse), StatusCodes.Status200OK)]
        [ProducesResponseType(typeof(void), StatusCodes.Status403Forbidden)]
        [ProducesResponseType(typeof(void), StatusCodes.Status401Unauthorized)]
        [Consumes("application/json")]
        [Produces("application/json")]
        [Authorize]
        public async Task<ActionResult<ItemResponse>> AddItem(ItemRecord details)
        {
            User user = (await service.GetUserAsync(User.Identity!.Name!)).Message!;
            if (!user.IsAdmin) return Forbid();

            var response = await service.AddItemAsync(details);
            return Ok(response);
        }

        /// <summary>
        /// Egy létező tárgy törlése (Admin jog szükséges)
        /// </summary>
        /// <param name="itemId">A tárgy azonosítója.</param>
        /// <returns>204 ha sikerült, 404 ha nem található.</returns>
        /// <response code="204">Sikeres törlés.</response>
        /// <response code="404">A tárgy nem található.</response>
        /// <response code="401">A felhasználó nincs bejelentkezve, vagy a munkamenete lejárt.</response>
        /// <response code="403">A jelenleg bejelentkezett felhasználó nem rendelkezik admin jogokkal</response>
        [HttpDelete]
        [Route("admin/items/{itemId:int}")]
        [Consumes("application/json")]
        [ProducesResponseType(typeof(void), StatusCodes.Status204NoContent)]
        [ProducesResponseType(typeof(void), StatusCodes.Status404NotFound)]
        [ProducesResponseType(typeof(void), StatusCodes.Status401Unauthorized)]
        [ProducesResponseType(typeof(void), StatusCodes.Status403Forbidden)]
        [Authorize]
        public async Task<ActionResult> DeleteItem(int itemId)
        {
            User user = (await service.GetUserAsync(User.Identity!.Name!)).Message!;
            if (!user.IsAdmin) return Forbid();

            var response = await service.DeleteItemAsync(itemId);
            return response.Status == "OK" ? NoContent() : NotFound();
        }

        /// <summary>
        /// Az összes létező felhasználó adatainak lekérdezése. (Admin jog szükséges)
        /// </summary>
        /// <returns>Egy listát, ami tartalmazza az összes felhasználó adatait.</returns>
        /// <response code="200">Visszaad egy listát, ami tartalmazza az összes felhasználó adatait.</response>
        /// <response code="403">A jelenleg bejelentkezett felhasználó nem rendelkezik admin jogokkal.</response>
        /// <response code="401">A felhasználó nincs bejelentkezve, vagy a munkamenete lejárt.</response>
        [HttpGet]
        [Route("admin/users")]
        [ProducesResponseType(typeof(List<UserResponse>), StatusCodes.Status200OK)]
        [ProducesResponseType(typeof(void), StatusCodes.Status403Forbidden)]
        [ProducesResponseType(typeof(void), StatusCodes.Status401Unauthorized)]
        [Consumes("application/json")]
        [Produces("application/json")]
        [Authorize]
        public async Task<ActionResult<List<UserResponse>>> GetUsers()
        {
            User user = (await service.GetUserAsync(User.Identity!.Name!)).Message!;
            if (!user.IsAdmin) return Forbid();

            return await service.GetUsersAsync();
        }

        /// <summary>
        /// Egy létező felhasználó adatainak módosítása (Admin jog szükséges)
        /// </summary>
        /// <param name="userId">A felhasználó azonosítója.</param>
        /// <param name="details">A felhasználó új adatai.</param>
        /// <returns>A felhasználó új adatait.</returns>
        /// <response code="200">Visszaadja a felhasználó új adatait.</response>
        /// <response code="403">A jelenleg bejelentkezett felhasználó nem rendelkezik admin jogokkal.</response>
        /// <response code="404">A felhasználó nem található.</response>
        /// <response code="401">A felhasználó nincs bejelentkezve, vagy a munkamenete lejárt.</response>
        /// <response code="409">A megadott adatok ütköznek egy másik meglévő felhasználónak adataival. (A válasz tartalmazza az ütközés pontos leírását)</response>
        [HttpPut]
        [Route("admin/users/{userId:int}")]
        [Consumes("application/json")]
        [Produces("application/json")]
        [ProducesResponseType(typeof(ActionStatus), StatusCodes.Status200OK)]
        [ProducesResponseType(typeof(void), StatusCodes.Status403Forbidden)]
        [ProducesResponseType(typeof(void), StatusCodes.Status404NotFound)]
        [ProducesResponseType(typeof(void), StatusCodes.Status401Unauthorized)]
        [ProducesResponseType(typeof(ActionResult), StatusCodes.Status409Conflict)]
        [Authorize]
        public async Task<ActionResult<ActionStatus>> UpdateUser(int userId, UserEditRecord details)
        {
            User user = (await service.GetUserAsync(User.Identity!.Name!)).Message!;
            if (!user.IsAdmin) return Forbid();

            var response = await service.UpdateUserAsync(userId, details);
            return response.Status == "OK" ? Ok(response) : response.Status == "ERR" ? NotFound() : Conflict(response);
        }

        /// <summary>
        /// Hozzáad egy tárgyat egy felhasználó leltárához. (Admin jog szükséges)
        /// </summary>
        /// <param name="userId">A felhasználó azonosítója.</param>
        /// <param name="itemId">A hozzáadandó tárgy azonosítója.</param>
        /// <returns>A felhasználó leltárának frissített adatait.</returns>
        /// <response code="200">Visszaadja a felhasználó leltárának frissített adatait.</response>
        /// <response code="403">A jelenleg bejelentkezett felhasználó nem rendelkezik admin jogokkal</response>
        /// <response code="404">A tárgy vagy a felhasználó nem található.</response>
        /// <response code="401">A felhasználó nincs bejelentkezve, vagy a munkamenete lejárt.</response>
        [HttpPost]
        [Route("admin/users/{userId:int}/inventory/{itemId:int}")]
        [Consumes("application/json")]
        [Produces("application/json")]
        [ProducesResponseType(typeof(CaseResponse), StatusCodes.Status200OK)]
        [ProducesResponseType(typeof(void), StatusCodes.Status403Forbidden)]
        [ProducesResponseType(typeof(void), StatusCodes.Status404NotFound)]
        [ProducesResponseType(typeof(void), StatusCodes.Status401Unauthorized)]
        [Authorize]
        public async Task<ActionResult> AddInventoryItem(int userId, int itemId)
        {
            User user = (await service.GetUserAsync(User.Identity!.Name!)).Message!;
            if (!user.IsAdmin) return Forbid();

            var response = await service.AddInventoryItemAsync(userId, itemId);
            return response.Status == "OK" ? Ok(response) : NotFound();
        }

        /// <summary>
        /// Eltávolít egy tárgyat egy felhasználó leltárából. (Admin jog szükséges)
        /// </summary>
        /// <param name="userId">A felhasználó azonosítója.</param>
        /// <param name="itemId">A hozzáadandó tárgy azonosítója.</param>
        /// <returns>A felhasználó leltárának frissített adatait.</returns>
        /// <response code="200">Visszaadja a felhasználó leltárának frissített adatait.</response>
        /// <response code="403">A jelenleg bejelentkezett felhasználó nem rendelkezik admin jogokkal</response>
        /// <response code="404">A tárgy vagy a felhasználó nem található, vagy a tárgy nincs a felhasználó leltárában.</response>
        /// <response code="401">A felhasználó nincs bejelentkezve, vagy a munkamenete lejárt.</response>
        [HttpDelete]
        [Consumes("application/json")]
        [Produces("application/json")]
        [ProducesResponseType(typeof(CaseResponse), StatusCodes.Status200OK)]
        [ProducesResponseType(typeof(void), StatusCodes.Status403Forbidden)]
        [ProducesResponseType(typeof(void), StatusCodes.Status404NotFound)]
        [ProducesResponseType(typeof(void), StatusCodes.Status401Unauthorized)]
        [Route("admin/users/{userId:int}/inventory/{itemId:int}")]
        [Authorize]
        public async Task<ActionResult> DeleteInventoryItem(int userId, int itemId)
        {
            User user = (await service.GetUserAsync(User.Identity!.Name!)).Message!;
            if (!user.IsAdmin) return Forbid();

            var response = await service.DeleteInventoryItemAsync(userId, itemId);
            return response.Status == "OK" ? Ok(response) : NotFound();
        }

        /// <summary>
        /// Létező tárgy módosítása (Admin jog szükséges)
        /// </summary>
        /// <param name="itemId">A módosítandó tárgy azonosítója.</param>
        /// <param name="details">A tárgy új adatai.</param>
        /// <returns>A tárgy frissített adatait.</returns>
        /// <response code="200">Visszaadja a tárgy frissített adatait.</response>
        /// <response code="403">A jelenleg bejelentkezett felhasználó nem rendelkezik admin jogokkal</response>
        /// <response code="404">A tárgy nem található.</response>
        /// <response code="401">A felhasználó nincs bejelentkezve, vagy a munkamenete lejárt.</response>
        [HttpPut]
        [Route("admin/items/{itemId:int}")]
        [Consumes("application/json")]
        [Produces("application/json")]
        [ProducesResponseType(typeof(ItemResponse), StatusCodes.Status200OK)]
        [ProducesResponseType(typeof(void), StatusCodes.Status403Forbidden)]
        [ProducesResponseType(typeof(void), StatusCodes.Status404NotFound)]
        [ProducesResponseType(typeof(void), StatusCodes.Status401Unauthorized)]
        [Authorize]
        public async Task<ActionResult> UpdateItem(int itemId, ItemRecord details)
        {
            User user = (await service.GetUserAsync(User.Identity!.Name!)).Message!;
            if (!user.IsAdmin) return Forbid();

            var response = await service.UpdateItemAsync(itemId, details);
            return response.Status == "OK" ? Ok(response) : NotFound();
        }

        /// <summary>
        /// Kép feltöltése (Admin jog szükséges)
        /// </summary>
        /// <param name="image">A feltöltendő kép.</param>
        /// <returns>A kép elérési útja.</returns>
        /// <response code="200">Visszaadja a kép elérési útját.</response>
        /// <response code="400">Nem lett kép feltöltve.</response>
        /// <response code="500">Belső szerver hiba.</response>
        /// <response code="403">A jelenleg bejelentkezett felhasználó nem rendelkezik admin jogokkal</response>
        /// <response code="401">A felhasználó nincs bejelentkezve, vagy a munkamenete lejárt.</response>
        [HttpPost("admin/images")]
        [Consumes("multipart/form-data")]
        [Produces("application/json")]
        [ProducesResponseType(typeof(ActionStatus), StatusCodes.Status200OK)]
        [ProducesResponseType(typeof(ActionStatus), StatusCodes.Status400BadRequest)]
        [ProducesResponseType(typeof(ActionStatus), StatusCodes.Status500InternalServerError)]
        [ProducesResponseType(typeof(void), StatusCodes.Status403Forbidden)]
        [ProducesResponseType(typeof(ActionStatus), StatusCodes.Status401Unauthorized)]
        [Authorize]
        public async Task<IActionResult> ImageUpload(IFormFile image)
        {
            User user = (await service.GetUserAsync(User.Identity!.Name!)).Message!;
            if (!user.IsAdmin) return Forbid();

            var response = await service.UploadImageAsync(image);
            return response.Status == "OK" ? Ok(response) : response.Status == "ERR" ? BadRequest(response) : StatusCode(500, response);
        }
    }
}
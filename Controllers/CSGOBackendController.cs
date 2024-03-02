using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using csgo.Models;
using Fido2NetLib;
using Fido2NetLib.Objects;
using KaimiraGames;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using OtpNet;
using static csgo.Dtos;
using Item = csgo.Models.Item;

namespace csgo.Controllers
{
    /// <summary>
    /// Backend végpontok.
    /// </summary>
    /// <param name="context">Adatbázis kontextus.</param>
    /// <param name="fido2">Fido2 szolgáltatás.</param>
    [ApiController]
    [Route("api")]
    public class CsgoBackendController(CsgoContext context, IFido2 fido2) : ControllerBase
    {
        private readonly Dictionary<ItemRarity, int> rarityWeights = new()
        {
            { ItemRarity.INDUSTRIAL_GRADE, 7992 },
            { ItemRarity.MIL_SPEC, 7992 },
            { ItemRarity.RESTRICTED, 1598 },
            { ItemRarity.CLASSIFIED, 320 },
            { ItemRarity.COVERT, 64 },
            { ItemRarity.EXTRAORDINARY, 28 }
        };

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
        public ActionResult<UserResponse> Profile()
        {
            User user = context.Users.First(x => x.Username == User.Identity!.Name);

            return Ok(user.ToDto(null!));
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
        public ActionResult<List<InventoryItemResponse>> Inventory()
        {
            User user = context.Users.First(x => x.Username == User.Identity!.Name);

            List<InventoryItemResponse> items = [.. context.Userinventories.Where(x => x.UserId == user.UserId).Select(x => x.Item.ToInventoryItemDto(x.InventoryId))];

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
        public async Task<ActionResult<ActionStatus>> LoginUser(LoginRequest login)
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
                case MfaType.WebAuthnOptions:
                {
                    if (!storedUser.WebauthnEnabled) return BadRequest(new ActionStatus{ Status = "ERR", Message = "InvalidMFAMethod" });                 
                    if (storedUser.WebauthnCredentialId == null || storedUser.WebauthnPublicKey == null) return BadRequest(new ActionStatus{ Status = "ERR", Message = "InvalidWebAuthn" });

                    var credential = JsonSerializer.Deserialize<StoredCredential>(storedUser.WebauthnPublicKey);

                    if (credential == null) return BadRequest(new ActionStatus{ Status = "ERR", Message = "InvalidWebAuthn" });

                    var options = fido2.GetAssertionOptions([credential.Descriptor], UserVerificationRequirement.Discouraged);

                    HttpContext.Session.SetString("fido2.assertionOptions", options.ToJson());

                    return Unauthorized(new ActionStatus{ Status = "UI", Message = options.ToJson() });
                }
                case MfaType.WebAuthnAssertion: {
                    if (!storedUser.WebauthnEnabled) return BadRequest(new ActionStatus{ Status = "ERR", Message = "InvalidMFAMethod" });
                    if (storedUser.WebauthnCredentialId == null || storedUser.WebauthnPublicKey == null || login.Mfa.WebAuthnAssertationResponse == null) return BadRequest(new ActionStatus{ Status = "ERR", Message = "InvalidWebAuthn" });

                    var jsonOptions = HttpContext.Session.GetString("fido2.assertionOptions");
                    var options = AssertionOptions.FromJson(jsonOptions);
                    var credential = JsonSerializer.Deserialize<StoredCredential>(storedUser.WebauthnPublicKey);

                    if (credential == null) return BadRequest(new ActionStatus{ Status = "ERR", Message = "InvalidWebAuthn" });

                    var result = await fido2.MakeAssertionAsync(
                        login.Mfa.WebAuthnAssertationResponse, 
                        options, 
                        credential.PublicKey,
                        credential.DevicePublicKeys,
                        credential.SignCount,
                        IsUserHandleOwnerOfCredentialId,
                        CancellationToken.None);

                    if (result.Status != "ok") return BadRequest(new ActionStatus{ Status = "ERR", Message = "InvalidWebAuthn" });

                    var storedCredential = new StoredCredential
                    {
                        DevicePublicKeys = credential.DevicePublicKeys,
                        Id = result.CredentialId,
                        Descriptor = new PublicKeyCredentialDescriptor(result.CredentialId),
                        PublicKey = credential.PublicKey,
                        UserHandle = credential.UserHandle,
                        SignCount = result.SignCount,
                        RegDate = credential.RegDate,
                        AaGuid = credential.AaGuid
                    };

                    storedUser.WebauthnPublicKey = JsonSerializer.Serialize(storedCredential);
                    await context.SaveChangesAsync();

                    return CheckPassword(login.Password, storedUser);
                }
                default:
                {
                    return BadRequest(new ActionStatus{ Status = "ERR", Message = "InvalidCredential" });
                }
            }
        }

        private async Task<bool> IsUserHandleOwnerOfCredentialId(IsUserHandleOwnerOfCredentialIdParams arg, CancellationToken cancellationToken)
        {
            var user = await context.Users.FirstAsync(x => x.Username == User.Identity!.Name, cancellationToken: cancellationToken);

            if (user.WebauthnPublicKey == null) return false;

            var credential = JsonSerializer.Deserialize<StoredCredential>(user.WebauthnPublicKey);

            return credential?.UserHandle.SequenceEqual(arg.UserHandle) ?? false;
        }

        /// <summary>
        /// WebAuthn attesztáció (1. lépés).
        /// </summary>
        [HttpGet]
        [Authorize]
        [Route("webauthn")]
        public async Task<ActionResult> WebAuthnAttestation()
        {
            var user = await context.Users.FirstAsync(x => x.Username == User.Identity!.Name);
            var fidoUser = new Fido2User
            {
                DisplayName = user.Username,
                Name = user.Username,
                Id = Encoding.UTF8.GetBytes(user.UserId.ToString())
            };

            var options = fido2.RequestNewCredential(fidoUser, [], new AuthenticatorSelection {
                ResidentKey = ResidentKeyRequirement.Preferred,
                UserVerification = UserVerificationRequirement.Preferred
            }, AttestationConveyancePreference.None, new AuthenticationExtensionsClientInputs{
                CredProps = true
            });

            HttpContext.Session.SetString("fido2.attestationOptions", options.ToJson());

            return Ok(options);
        }

        /// <summary>
        /// WebAuthn attesztáció (2. lépés).
        /// </summary>
        /// <param name="attestationResponse">A WebAuthn attesztáció válasza.</param>
        [HttpPost]
        [Authorize]
        [Route("webauthn")]
        public async Task<ActionResult> WebAuthnAttestation([FromBody] AuthenticatorAttestationRawResponse attestationResponse)
        {
            var user = await context.Users.FirstAsync(x => x.Username == User.Identity!.Name);
            try{
                var jsonOptions = HttpContext.Session.GetString("fido2.attestationOptions");
                if (jsonOptions == null) return NotFound();
                var options = CredentialCreateOptions.FromJson(jsonOptions);

                var fidoCredentials = await fido2.MakeNewCredentialAsync(attestationResponse, options, IsCredentialIdUniqueToUser, CancellationToken.None);

                if(fidoCredentials.Result == null || fidoCredentials.Status != "ok") return BadRequest();

                var storedCredential = new StoredCredential
                {
                    Id = fidoCredentials.Result.Id,
                    Descriptor = new PublicKeyCredentialDescriptor(fidoCredentials.Result.Id),
                    PublicKey = fidoCredentials.Result.PublicKey,
                    UserHandle = fidoCredentials.Result.User.Id,
                    SignCount = fidoCredentials.Result.SignCount,
                    RegDate = DateTime.Now,
                    AaGuid = fidoCredentials.Result.AaGuid
                };

                user.WebauthnCredentialId = Convert.ToBase64String(fidoCredentials.Result.Id);
                user.WebauthnPublicKey = JsonSerializer.Serialize(storedCredential);
                user.WebauthnEnabled = true;

                await context.SaveChangesAsync();

                return Ok();
            }catch(Exception e)
            {
                return BadRequest(new MakeNewCredentialResult("error", e.Message, null));
            }
        }

        private async Task<bool> IsCredentialIdUniqueToUser(IsCredentialIdUniqueToUserParams credentialIdUserParams, CancellationToken cancellationToken)
        {
            return !await context.Users.AnyAsync(x => x.WebauthnCredentialId == Convert.ToBase64String(credentialIdUserParams.CredentialId), cancellationToken: cancellationToken);
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
        public ActionResult<ActionStatus> GenerateTotpToken() {
            var user = context.Users.First(x => x.Username == User.Identity!.Name);
            if(user.TotpEnabled) return Conflict();

            user.TotpSecret = Base32Encoding.ToString(KeyGeneration.GenerateRandomKey(20));
            context.SaveChanges();

            return Ok(new ActionStatus { Status = "OK", Message = user.TotpSecret });
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
        public ActionResult<ActionStatus> CheckTotpToken(EnableTOTPRequest request) {
            var user = context.Users.First(x => x.Username == User.Identity!.Name);
            if(user.TotpEnabled) return Conflict();

            var totp = new Totp(Base32Encoding.ToBytes(user.TotpSecret));
            bool verify = totp.VerifyTotp(request.Code, out _, VerificationWindow.RfcSpecifiedNetworkDelay);

            if(verify) {
                user.TotpEnabled = true;
                context.SaveChanges();
                return NoContent();
            }else{
                return Forbid();
            }
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
        [Produces("application/json")]
        [Authorize]
        public ActionResult<ActionStatus> DisableTotp(DisableTOTPRequest request) {
            var user = context.Users.First(x => x.Username == User.Identity!.Name);
            if(!user.TotpEnabled) return Conflict();

            if (!BCrypt.Net.BCrypt.Verify(request.Password, user.PasswordHash)) return Forbid();

            var totp = new Totp(Base32Encoding.ToBytes(user.TotpSecret));
            bool verify = totp.VerifyTotp(request.Code, out _, VerificationWindow.RfcSpecifiedNetworkDelay);

            if(verify) {
                user.TotpEnabled = false;
                context.SaveChanges();
                return NoContent();
            }else{
                return Forbid();
            }
        }

        /// <summary>
        /// A jelenleg bejelentkezett felhasználó admin jogainak ellenőrzése.
        /// </summary>
        /// <returns>204-es állapotkódot ha a jelenleg bejelentkezett felhasználó rendelkezik admin jogokkal, különben 403-as állapotkódot.</returns>
        /// <response code="204">A jelenleg bejelentkezett felhasználó rendelkezik admin jogokkal.</response>
        /// <response code="403">A jelenleg bejelentkezett felhasználó nem rendelkezik admin jogokkal.</response>
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
        /// <response code="403">A jelenleg bejelentkezett felhasználó nem rendelkezik admin jogokkal.</response>
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
        public ActionResult<List<UserResponse>> GetUsers()
        {
            User user = context.Users.First(x => x.Username == User.Identity!.Name);
            if (!user.IsAdmin) return Forbid();

            return Ok(context.Users.Select(x => x.ToDto(
                context.Userinventories.Where(y => y.UserId == x.UserId)
                    .Select(z => z.Item.ToDto()).ToList())).ToList());
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
        [Route("admin/inventory/{userId:int}/items/{itemId:int}")]
        [Consumes("application/json")]
        [Produces("application/json")]
        [ProducesResponseType(typeof(CaseResponse), StatusCodes.Status200OK)]
        [ProducesResponseType(typeof(void), StatusCodes.Status403Forbidden)]
        [ProducesResponseType(typeof(void), StatusCodes.Status404NotFound)]
        [ProducesResponseType(typeof(void), StatusCodes.Status401Unauthorized)]
        [Authorize]
        public ActionResult AddInventoryItem(int userId, int itemId)
        {
            User user = context.Users.First(x => x.Username == User.Identity!.Name);
            if (!user.IsAdmin) return Forbid();

            var target = context.Users.FirstOrDefault(x => x.UserId == userId);
            var item = context.Items.FirstOrDefault(x => x.ItemId == itemId);
            if (target == null || item == null) return NotFound();

            context.Userinventories.Add(new Userinventory {
                UserId = target.UserId,
                ItemId = item.ItemId
            });
            context.SaveChanges();

            List<InventoryItemResponse> items = [.. context.Userinventories.Where(x => x.UserId == user.UserId).Select(x => x.Item.ToInventoryItemDto(x.InventoryId))];
            
            return Ok(items);

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
        [Route("admin/inventory/{userId:int}/items/{itemId:int}")]
        [Authorize]
        public ActionResult DeleteInventoryItem(int userId, int itemId)
        {
            User user = context.Users.First(x => x.Username == User.Identity!.Name);
            if (!user.IsAdmin) return Forbid();

            var target = context.Users.FirstOrDefault(x => x.UserId == userId);
            var item = context.Items.FirstOrDefault(x => x.ItemId == itemId);
            if (target == null || item == null) return NotFound();

            var userInventory = context.Userinventories.FirstOrDefault(x => x.UserId == target.UserId && x.ItemId == item.ItemId);
            if (userInventory == null) return NotFound();
            
            context.Userinventories.Remove(userInventory);
            context.SaveChanges();

            List<InventoryItemResponse> items = [.. context.Userinventories.Where(x => x.UserId == user.UserId).Select(x => x.Item.ToInventoryItemDto(x.InventoryId))];
            
            return Ok(items);
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
        public ActionResult<ItemResponse> AddItem(ItemRecord details)
        {
            User user = context.Users.First(x => x.Username == User.Identity!.Name);
            if (!user.IsAdmin) return Forbid();


            Item item = new()
            {
                ItemType = ItemType.Item,
                ItemName = details.Name,
                ItemDescription = details.Description,
                ItemRarity = details.Rarity,
                ItemSkinName = details.SkinName,
                ItemValue = details.Value
            };
            context.Items.Add(item);
            context.SaveChanges();

            return Ok(item.ToDto());
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
                        .Select(z => z.Item).Select(z => z.ToDto()).ToList())).ToList());
        }

        /// <summary>
        /// Egy láda kinyitása.
        /// </summary>
        /// <param name="caseId">A láda azonosítója.</param>
        /// <returns>A megszerzett tárgy adatait.</returns>
        /// <response code="200">Visszaadja a megszerzett tárgy adatait.</response>
        /// <response code="404">A megadott láda nem létezik.</response>
        /// <response code="403">A jelenleg bejelentkezett felhasználónak a leltárában nem található az adott láda.</response>
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
        public ActionResult<ItemResponse> OpenCase(int caseId)
        {
            var user = context.Users.First(x => x.Username == User.Identity!.Name);

            var @case = context.Items.FirstOrDefault(x => x.ItemType == ItemType.Case && x.ItemId == caseId);
            if(@case == null) return NotFound();

            var userInventory = context.Userinventories.Where(x => x.UserId == user.UserId).Include(x => x.Item).ToList();
            var userCase = userInventory.Find(x => x.Item == @case);

            if (userCase == null) return Forbid();
            {
                var ctxCaseItems = context.CaseItems.Where(x => x.Case == @case).Include(y => y.Item).ToArray();

                var weights = new Dictionary<Item, double>();
                foreach (var item in ctxCaseItems)
                {
                    double rarityWeight = rarityWeights[item.Item.ItemRarity];
                    var valueWeight = (double)item.Item.ItemValue! / (double)@case.ItemValue!;
                    var totalWeight = rarityWeight * valueWeight;
                    weights[item.Item] = totalWeight;
                }

                var itemList = ctxCaseItems.Select(item => new WeightedListItem<Item>(item.Item, (int)weights[item.Item])).ToList();

                var caseItems = new WeightedList<Item>(itemList);
                var resultItem = caseItems.Next();

                context.Userinventories.Remove(userCase);
                context.Userinventories.Add(new Userinventory
                {
                    ItemId = resultItem.ItemId,
                    UserId = user.UserId
                });
                context.SaveChanges();

                return Ok(resultItem.ToDto());
            }
        }

        /// <summary>
        /// Egy tárgy továbbfejlesztésének esélyének lekérdezése.
        /// </summary>
        /// <param name="from">Az tárgy leltárazonosítója.</param>
        /// <param name="multiplier">A szorzó érték.</param>
        /// <returns>Visszaadja a fejleszett tárgya továbbfejlesztésének esélyét.</returns>
        /// <response code="200">Visszaadja a fejleszett órgya továbbfejlesztésének esélyét.</response>
        /// <response code="404">Nem található a megadott tárgy.</response>
        /// <response code="401">A felhasználó nincs bejelentkezve, vagy a munkamenete lejárt.</response>
        [HttpGet]
        [Route("items/upgrade/{from:int}/{multiplier:int}")]
        [ProducesResponseType(typeof(OkObjectResult), StatusCodes.Status200OK)]
        [ProducesResponseType(typeof(void), StatusCodes.Status404NotFound)]
        [ProducesResponseType(typeof(void), StatusCodes.Status401Unauthorized)]
        [Authorize]
        public ActionResult<ActionStatus> GetUpgradeChance(int from, int multiplier) {
            User user = context.Users.First(x => x.Username == User.Identity!.Name);

            Userinventory? inventoryItem = context.Userinventories.Include(x => x.Item).FirstOrDefault(x => x.InventoryId == from && x.UserId == user.UserId);

            if(inventoryItem == null) return NotFound();

            var nextItemValue = inventoryItem.Item.ItemValue * multiplier;
            var nextItem = context.Items.Where(x => x.ItemValue >= nextItemValue && x.ItemRarity >= inventoryItem.Item.ItemRarity).OrderBy(x => x.ItemValue).FirstOrDefault();
            if(nextItem == null) return NotFound();

            InventoryItemResponse itemData = inventoryItem.Item.ToInventoryItemDto(inventoryItem.InventoryId);

            var chance = GetItemUpgradeSuccessChance(itemData, nextItem);

            return Ok(new { Status = "OK", Chance = chance, NextItem = nextItem.ToDto() });
        }

        /// <summary>
        /// Egy tárgy továbbfejlesztése
        /// </summary>
        /// <param name="from">Az első tárgy leltárazonosítója.</param>
        /// <param name="multiplier">A szorzó érték.</param>
        /// <returns>Visszaadja a fejleszett tárgya adatait ha sikerült, különben null.</returns>
        /// <response code="200">Visszaadja a fejlesztett tárgy adatait ha sikerült, különben null.</response>
        /// <response code="404">Nem találhato a megadott tárgy.</response>
        /// <response code="401">A felhasználó nincs bejelentkezve, vagy a munkamenete lejárt.</response>
        [HttpPost]
        [Route("items/upgrade/{from:int}/{multiplier:int}")]
        [ProducesResponseType(typeof(ItemUpgradeResponse), StatusCodes.Status200OK)]
        [ProducesResponseType(typeof(void), StatusCodes.Status404NotFound)]
        [ProducesResponseType(typeof(void), StatusCodes.Status401Unauthorized)]
        [Authorize]
        public ActionResult<ItemUpgradeResponse> UpgradeItem(int from, int multiplier) {
            User user = context.Users.First(x => x.Username == User.Identity!.Name);

            Userinventory? inventoryItem = context.Userinventories.Include(x => x.Item).FirstOrDefault(x => x.InventoryId == from && x.UserId == user.UserId);

            if(inventoryItem == null) return NotFound();

            InventoryItemResponse itemData = inventoryItem.Item.ToInventoryItemDto(inventoryItem.InventoryId);

            var nextItemValue = inventoryItem.Item.ItemValue * multiplier;
            var nextItem = context.Items.Where(x => x.ItemValue >= nextItemValue && x.ItemRarity >= inventoryItem.Item.ItemRarity).OrderBy(x => x.ItemValue).FirstOrDefault();
            if(nextItem == null) return NotFound();

            var chance = GetItemUpgradeSuccessChance(itemData, nextItem);

            if(GetRandomDouble() < chance) {
                context.Userinventories.Remove(inventoryItem);
                context.Userinventories.Add(new Userinventory {
                    ItemId = nextItem.ItemId,
                    UserId = user.UserId
                });
                context.SaveChanges();

                return Ok(new ItemUpgradeResponse {
                    Success = true,
                    Item = nextItem.ToDto()
                });
            } else {
                context.Userinventories.Remove(inventoryItem);
                context.SaveChanges();
                
                return Ok(new ItemUpgradeResponse {
                    Success = false,
                    Item = null
                });
            }
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
        public ActionResult ClaimDailyReward() {
            User user = context.Users.First(x => x.Username == User.Identity!.Name);
            if(user.LastClaimDate.Date == DateTime.Now.Date) return Conflict();

            // Ha az utolsó kérés dátuma nem az aktuális hónapban van, akkor a streaket nullázni kell.
            if(user.LastClaimDate.Month != DateTime.Now.Month) user.LoginStreak = 1;

            int reward = 5;
            
            if(user.LastClaimDate.Date.AddDays(1) == DateTime.Now.Date) {
                user.LoginStreak++;
                if(user.LoginStreak == 3) reward *= 2;
                if(user.LoginStreak == 7) reward *= 3;
                if(user.LoginStreak == 14) reward *= 4;
                if(user.LoginStreak == 30) reward *= 5;
            } else {
                user.LoginStreak = 1;
            }

            user.LastClaimDate = DateTime.Now;
            user.Balance += reward;

            context.SaveChanges();

            return Ok(new { Status = "OK", Amount = reward });
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
            User user = context.Users.First(x => x.Username == User.Identity!.Name);

            var giveaway = await context.Giveaways.Where(x => x.GiveawayDate > DateTime.Now && x.GiveawayId == id).Include(x => x.Users).FirstOrDefaultAsync();
            if (giveaway == null) return NotFound();
            if (giveaway.Users.Contains(user)) return Conflict();

            giveaway.Users.Add(user);
            await context.SaveChangesAsync();

            return NoContent();
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
            var giveaways = await context.Giveaways.Where(x => x.GiveawayDate > DateTime.Now).Include(x => x.Item).ToListAsync();

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
                .Where(x => x.GiveawayDate <= DateTime.Now && x.WinnerUserId != null)
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
        public ActionResult AddCase(CaseRecord details)
        {
            User user = context.Users.First(x => x.Username == User.Identity!.Name);
            if (!user.IsAdmin) return Forbid();


            Item @case = new()
            {
                ItemName = details.Name,
                ItemType = ItemType.Case,
                ItemValue = details.Value,
            };
            context.Items.Add(@case);
            context.SaveChanges();

            return Ok(@case.ToCaseDto(new List<ItemResponse>()));
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
            
            var caseItems = context.CaseItems.Where(x => x.Case == @case).Select(x => x.Item.ToDto()).ToList();

            return Ok(@case.ToCaseDto(caseItems));

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
        public ActionResult DeleteCaseItem(int caseId, int itemId)
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

            var caseItems = context.CaseItems.Where(x => x.Case == @case).Select(x => x.Item.ToDto()).ToList();

            return Ok(@case.ToCaseDto(caseItems));
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
        public ActionResult<CurrentGiveawayResponse> AddGiveaway(GiveawayRecord details) {
            User user = context.Users.First(x => x.Username == User.Identity!.Name);
            if (!user.IsAdmin) return Forbid();

            var item = context.Items.Find(details.ItemId);
            if (item == null) return NotFound();

            var giveaway = new Giveaway{
                ItemId = item.ItemId,
                GiveawayDate = details.Date.ToLocalTime(),
                GiveawayDescription = details.Description,
                GiveawayName = details.Name,
            };

            context.Giveaways.Add(giveaway);
            context.SaveChanges();

            return Ok(new CurrentGiveawayResponse {
                GiveawayDate = giveaway.GiveawayDate,
                GiveawayDescription = giveaway.GiveawayDescription,
                GiveawayId = giveaway.GiveawayId,
                GiveawayItem = giveaway.Item!.ItemName,
                GiveawayName = giveaway.GiveawayName
            });
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

        private double GetItemUpgradeSuccessChance(InventoryItemResponse currentItem, Item nextItem)
        {
            var current = context.Items.Find(currentItem.ItemId);
            var next = context.Items.Find(nextItem.ItemId);

            // Alap esély
            double baseChance = 0.8;

            // Ritkaság szerinti esély
            double rarityMultiplier = 0.05 * Math.Abs(next!.ItemRarity - current!.ItemRarity);

            // Érték szerinti esély
            double valueMultiplier = 0.05 * Math.Abs((double)(next.ItemValue - current.ItemValue)!) / 10;

            double successChance = Math.Max(0, Math.Min(1, Math.Round(baseChance - rarityMultiplier - valueMultiplier, 2)));

            return successChance;
        }

        
        private static double GetRandomDouble()
        {
            byte[] bytes = new byte[8];
            using (RandomNumberGenerator rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(bytes);
            }

            long longValue = BitConverter.ToInt64(bytes, 0);
            return (double)longValue / long.MaxValue;
    }
    }
}
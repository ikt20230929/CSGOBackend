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
        public async Task<ActionResult<ActionStatus>> Register(RegisterRequest register)
        {
            User newUser = new()
            {
                Email = register.Email,
                Username = register.Username
            };

            if (await context.Users.AnyAsync(u => u.Username == register.Username))
            {
                return BadRequest(new ActionStatus { Status = "ERR", Message = "A megadott felhasználónév már foglalt." });
            }

            if (await context.Users.AnyAsync(u => u.Email == register.Email))
            {
                return BadRequest(new ActionStatus { Status = "ERR", Message = "Az megadott e-mail már használatban van." });
            }

            string hashedPassword = BCrypt.Net.BCrypt.HashPassword(register.Password);
            newUser.PasswordHash = hashedPassword;
            await context.Users.AddAsync(newUser);
            await context.SaveChangesAsync();

            return Ok(new ActionStatus { Status = "OK", Message = "Sikeres regisztráció!" });
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
        public async Task<ActionResult<UserResponse>> Profile()
        {
            User user = await context.Users.FirstAsync(x => x.Username == User.Identity!.Name);

            return Ok(user.ToDto(null!));
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
            return await context.Users.FirstAsync(x => x.Username == (string)username!);
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
            User user = await context.Users.FirstAsync(x => x.Username == User.Identity!.Name);

            List<InventoryItemResponse> items = await context.Userinventories.Where(x => x.UserId == user.UserId).Select(x => x.Item.ToInventoryItemDto(x.InventoryId)).ToListAsync();

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
        public async Task<ActionResult<ActionStatus>> RefreshToken()
        {
            var currentRefreshToken = HttpContext.Request.Cookies["refreshToken"];
            if (currentRefreshToken == null) return Unauthorized();
            User user = await GetUserFromRefreshJwt(currentRefreshToken);
            var (accessToken, refreshToken) = GenerateTokens(user);

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
            var storedUser = await context.Users.FirstOrDefaultAsync(u => u.Username == login.Username);

            if (storedUser == null)
            {
                return BadRequest(new ActionStatus { Status = "ERR", Message = "InvalidCredential" });
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
            if (login.Mfa == null) return Unauthorized(new ActionStatus { Status = "UI", Message = twoFactorScenario });
            switch (login.Mfa.MfaType)
            {
                case MfaType.Totp:
                    {
                        if (!storedUser.TotpEnabled) return BadRequest(new ActionStatus { Status = "ERR", Message = "InvalidMFAMethod" });
                        if (login.Mfa.TotpToken == null) return BadRequest(new ActionStatus { Status = "ERR", Message = "InvalidTotp" });
                        var totp = new Totp(Base32Encoding.ToBytes(storedUser.TotpSecret));
                        bool verify = totp.VerifyTotp(login.Mfa.TotpToken, out _,
                            VerificationWindow.RfcSpecifiedNetworkDelay);
                        return verify ? CheckPassword(login.Password, storedUser) : BadRequest(new ActionStatus { Status = "ERR", Message = "InvalidTotp" });
                    }
                case MfaType.WebAuthnOptions:
                    {
                        if (!storedUser.WebauthnEnabled) return BadRequest(new ActionStatus { Status = "ERR", Message = "InvalidMFAMethod" });
                        if (storedUser.WebauthnCredentialId == null || storedUser.WebauthnPublicKey == null) return BadRequest(new ActionStatus { Status = "ERR", Message = "InvalidWebAuthn" });

                        var credential = JsonSerializer.Deserialize<StoredCredential>(storedUser.WebauthnPublicKey);

                        if (credential == null) return BadRequest(new ActionStatus { Status = "ERR", Message = "InvalidWebAuthn" });

                        var options = fido2.GetAssertionOptions([credential.Descriptor], UserVerificationRequirement.Discouraged);

                        HttpContext.Session.SetString("fido2.assertionOptions", options.ToJson());

                        return Unauthorized(new ActionStatus { Status = "UI", Message = options.ToJson() });
                    }
                case MfaType.WebAuthnAssertion:
                    {
                        if (!storedUser.WebauthnEnabled) return BadRequest(new ActionStatus { Status = "ERR", Message = "InvalidMFAMethod" });
                        if (storedUser.WebauthnCredentialId == null || storedUser.WebauthnPublicKey == null || login.Mfa.WebAuthnAssertationResponse == null) return BadRequest(new ActionStatus { Status = "ERR", Message = "InvalidWebAuthn" });

                        var jsonOptions = HttpContext.Session.GetString("fido2.assertionOptions");
                        var options = AssertionOptions.FromJson(jsonOptions);
                        var credential = JsonSerializer.Deserialize<StoredCredential>(storedUser.WebauthnPublicKey);

                        if (credential == null) return BadRequest(new ActionStatus { Status = "ERR", Message = "InvalidWebAuthn" });

                        var result = await fido2.MakeAssertionAsync(
                            login.Mfa.WebAuthnAssertationResponse,
                            options,
                            credential.PublicKey,
                            credential.DevicePublicKeys,
                            credential.SignCount,
                            IsUserHandleOwnerOfCredentialId,
                            CancellationToken.None);

                        if (result.Status != "ok") return BadRequest(new ActionStatus { Status = "ERR", Message = "InvalidWebAuthn" });

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
                        return BadRequest(new ActionStatus { Status = "ERR", Message = "InvalidCredential" });
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
        public async Task<ActionResult> WebAuthnAttestation()
        {
            var user = await context.Users.FirstAsync(x => x.Username == User.Identity!.Name);
            var fidoUser = new Fido2User
            {
                DisplayName = user.Username,
                Name = user.Username,
                Id = Encoding.UTF8.GetBytes(user.UserId.ToString())
            };

            var options = fido2.RequestNewCredential(fidoUser, [], new AuthenticatorSelection
            {
                ResidentKey = ResidentKeyRequirement.Preferred,
                UserVerification = UserVerificationRequirement.Preferred
            }, AttestationConveyancePreference.None, new AuthenticationExtensionsClientInputs
            {
                CredProps = true
            });

            HttpContext.Session.SetString("fido2.attestationOptions", options.ToJson());

            return Ok(options);
        }

        /// <summary>
        /// WebAuthn attesztáció (2. lépés).
        /// </summary>
        /// <param name="attestationResponse">A WebAuthn attesztáció válasza.</param>
        /// <returns>200 ha sikerült, 400 ha nem.</returns>
        /// <response code="200">A WebAuthn attesztáció sikeres volt.</response>
        /// <response code="400">A WebAuthn attesztáció sikertelen volt.</response>
        /// <response code="401">A felhasználó nincs bejelentkezve, vagy a munkamenete lejárt.</response>
        /// <response code="404">A WebAuthn attesztáció beállításai nem találhatók a jelenlegi munkamenetben.</response>
        [HttpPost]
        [Authorize]
        [Route("webauthn")]
        [ProducesResponseType(typeof(void), StatusCodes.Status200OK)]
        [ProducesResponseType(typeof(void), StatusCodes.Status400BadRequest)]
        [ProducesResponseType(typeof(void), StatusCodes.Status401Unauthorized)]
        [ProducesResponseType(typeof(void), StatusCodes.Status404NotFound)]
        [Consumes("application/json")]
        [Produces("application/json")]
        public async Task<ActionResult> WebAuthnAttestation([FromBody] AuthenticatorAttestationRawResponse attestationResponse)
        {
            var user = await context.Users.FirstAsync(x => x.Username == User.Identity!.Name);
            try
            {
                var jsonOptions = HttpContext.Session.GetString("fido2.attestationOptions");
                if (jsonOptions == null) return NotFound();
                var options = CredentialCreateOptions.FromJson(jsonOptions);

                var fidoCredentials = await fido2.MakeNewCredentialAsync(attestationResponse, options, IsCredentialIdUniqueToUser, CancellationToken.None);

                if (fidoCredentials.Result == null || fidoCredentials.Status != "ok") return BadRequest();

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
            }
            catch (Exception e)
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
        public async Task<ActionResult<ActionStatus>> GenerateTotpToken()
        {
            var user = await context.Users.FirstAsync(x => x.Username == User.Identity!.Name);
            if (user.TotpEnabled) return Conflict();

            user.TotpSecret = Base32Encoding.ToString(KeyGeneration.GenerateRandomKey(20));
            await context.SaveChangesAsync();

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
        public async Task<ActionResult<ActionStatus>> CheckTotpToken(EnableTOTPRequest request)
        {
            var user = await context.Users.FirstAsync(x => x.Username == User.Identity!.Name);
            if (user.TotpEnabled) return Conflict();

            var totp = new Totp(Base32Encoding.ToBytes(user.TotpSecret));
            bool verify = totp.VerifyTotp(request.Code, out _, VerificationWindow.RfcSpecifiedNetworkDelay);

            if (verify)
            {
                user.TotpEnabled = true;
                await context.SaveChangesAsync();
                return NoContent();
            }
            else
            {
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
        [Authorize]
        public async Task<ActionResult<ActionStatus>> DisableTotp(DisableTOTPRequest request)
        {
            var user = await context.Users.FirstAsync(x => x.Username == User.Identity!.Name);
            if (!user.TotpEnabled) return Conflict();

            if (!BCrypt.Net.BCrypt.Verify(request.Password, user.PasswordHash)) return Forbid();

            var totp = new Totp(Base32Encoding.ToBytes(user.TotpSecret));
            bool verify = totp.VerifyTotp(request.Code, out _, VerificationWindow.RfcSpecifiedNetworkDelay);

            if (verify)
            {
                user.TotpEnabled = false;
                await context.SaveChangesAsync();
                return NoContent();
            }
            else
            {
                return Forbid();
            }
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
            var items = await context.Items
                .Where(x => x.ItemType == ItemType.Case)
                .ToListAsync();

            var caseDtos = new List<CaseResponse>();

            foreach (var item in items)
            {
                var caseItems = await context.CaseItems
                    .Where(y => y.CaseId == item.ItemId)
                    .Select(z => z.Item)
                    .Select(z => z.ToDto())
                    .ToListAsync();

                var caseDto = item.ToCaseDto(caseItems);
                caseDtos.Add(caseDto);
            }

            return Ok(caseDtos);
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
            var user = await context.Users.FirstAsync(x => x.Username == User.Identity!.Name);

            var @case = await context.Items.FirstOrDefaultAsync(x => x.ItemType == ItemType.Case && x.ItemId == caseId);
            if (@case == null) return NotFound();

            if ((decimal)user.Balance < @case.ItemValue) return Forbid();

            var ctxCaseItems = await context.CaseItems.Where(x => x.Case == @case).Include(y => y.Item).ToArrayAsync();

            var weights = new Dictionary<Item, double>();
            foreach (var item in ctxCaseItems)
            {
                double rarityWeight = rarityWeights[item.Item.ItemRarity];
                double valueRatio = (double)item.Item.ItemValue! / (double)@case.ItemValue!;
                double valueWeight = 1 / (1 + valueRatio);
                var totalWeight = rarityWeight * valueWeight;
                weights[item.Item] = totalWeight;
            }

            var itemList = ctxCaseItems.Select(item => new WeightedListItem<Item>(item.Item, (int)weights[item.Item])).ToList();

            var caseItems = new WeightedList<Item>(itemList);
            var resultItem = caseItems.Next();

            await context.Userinventories.AddAsync(new Userinventory
            {
                ItemId = resultItem.ItemId,
                UserId = user.UserId
            });

            user.Balance -= Convert.ToDouble(@case.ItemValue);

            await context.SaveChangesAsync();

            return Ok(resultItem.ToDto());
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
            return Ok(await context.Items.Where(x => x.ItemType == ItemType.Item).Select(x => x.ToDto()).ToListAsync());
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
            var user = await context.Users.FirstAsync(x => x.Username == User.Identity!.Name);

            var inventoryItem = await context.Userinventories.Include(x => x.Item).FirstOrDefaultAsync(x => x.InventoryId == inventoryId && x.UserId == user.UserId);
            if (inventoryItem == null) return NotFound();

            user.Balance += Convert.ToDouble(inventoryItem.Item.ItemValue);
            context.Userinventories.Remove(inventoryItem);
            await context.SaveChangesAsync();

            return NoContent();
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
            User user = await context.Users.FirstAsync(x => x.Username == User.Identity!.Name);

            foreach (var item in request.Items)
            {
                if (!await context.Userinventories.AnyAsync(x => x.InventoryId == item && x.UserId == user.UserId)) return NotFound();
            }

            List<InventoryItemResponse> itemData = request.Items.Select(x => context.Userinventories.Include(y => y.Item).First(y => y.InventoryId == x).Item.ToInventoryItemDto(x)).ToList();

            var totalValue = itemData.Sum(x => x.ItemValue);

            var upgradeItems = await context.Items
                .Where(x => x.ItemValue >= totalValue && x.ItemType == ItemType.Item)
                .OrderBy(x => x.ItemValue)
                .ToListAsync();

            if (upgradeItems.Count == 0) return Conflict();

            return Ok(new { Status = "OK", TotalValue = totalValue, Items = upgradeItems.Where(y => GetItemUpgradeSuccessChance(totalValue, y) > 0).Select(x => new { Item = x.ToDto(), Chance = GetItemUpgradeSuccessChance(totalValue, x), Multiplier = Math.Round((decimal)x.ItemValue! / totalValue, 2) }) });
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
            User user = await context.Users.FirstAsync(x => x.Username == User.Identity!.Name);

            foreach (var item in request.Items)
            {
                if (!await context.Userinventories.AnyAsync(x => x.InventoryId == item && x.UserId == user.UserId)) return NotFound();
            }

            List<InventoryItemResponse> itemData = request.Items.Select(x => context.Userinventories.Include(y => y.Item).First(y => y.InventoryId == x).Item.ToInventoryItemDto(x)).ToList();

            var nextItem = await context.Items.FirstOrDefaultAsync(x => x.ItemId == request.Target && x.ItemType == ItemType.Item);
            if (nextItem == null) return NotFound();

            var totalValue = itemData.Sum(x => x.ItemValue);

            var chance = GetItemUpgradeSuccessChance(totalValue, nextItem);

            if (GetRandomDouble() < chance)
            {
                foreach (var item in itemData)
                {
                    context.Userinventories.Remove(await context.Userinventories.FirstAsync(x => x.InventoryId == item.InventoryId));
                }
                await context.Userinventories.AddAsync(new Userinventory
                {
                    ItemId = nextItem.ItemId,
                    UserId = user.UserId
                });
                await context.SaveChangesAsync();

                return Ok(new ItemUpgradeResponse
                {
                    Success = true,
                    Item = nextItem.ToDto()
                });
            }
            else
            {
                foreach (var item in itemData)
                {
                    context.Userinventories.Remove(await context.Userinventories.FirstAsync(x => x.InventoryId == item.InventoryId));
                }
                await context.SaveChangesAsync();

                return Ok(new ItemUpgradeResponse
                {
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
        public async Task<ActionResult> ClaimDailyReward()
        {
            User user = await context.Users.FirstAsync(x => x.Username == User.Identity!.Name);
            if (user.LastClaimDate.Date == DateTime.Now.Date) return Conflict();

            // Ha az utolsó kérés dátuma nem az aktuális hónapban van, akkor a streaket nullázni kell.
            if (user.LastClaimDate.Month != DateTime.Now.Month) user.LoginStreak = 1;

            int reward = 5;

            if (user.LastClaimDate.Date.AddDays(1) == DateTime.Now.Date)
            {
                user.LoginStreak++;
                if (user.LoginStreak == 3) reward *= 2;
                if (user.LoginStreak == 7) reward *= 3;
                if (user.LoginStreak == 14) reward *= 4;
                if (user.LoginStreak == 30) reward *= 5;
            }
            else
            {
                user.LoginStreak = 1;
            }

            user.LastClaimDate = DateTime.Now;
            user.Balance += reward;

            await context.SaveChangesAsync();

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
            User user = await context.Users.FirstAsync(x => x.Username == User.Identity!.Name);

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
            var user = await context.Users.FirstAsync(x => x.Username == User.Identity!.Name);

            // Nyereményjátékok, amelyek még nem futottak le.
            var giveaways = await context.Giveaways.Where(x => x.GiveawayDate > DateTime.Now).Include(x => x.Item).Include(x => x.Users).ToListAsync();

            var mapped = giveaways.Select(giveaway => new CurrentGiveawayResponse
            {
                GiveawayId = giveaway.GiveawayId,
                GiveawayName = giveaway.GiveawayName,
                GiveawayDescription = giveaway.GiveawayDescription!,
                GiveawayDate = giveaway.GiveawayDate,
                GiveawayItem = giveaway.Item!.ItemName,
                GiveawayJoined = giveaway.Users.Contains(user)
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
        public async Task<ActionResult> AddCase(CaseRecord details)
        {
            User user = await context.Users.FirstAsync(x => x.Username == User.Identity!.Name);
            if (!user.IsAdmin) return Forbid();


            Item @case = new()
            {
                ItemName = details.Name,
                ItemType = ItemType.Case,
                ItemValue = details.Value,
                ItemAssetUrl = details.AssetUrl ?? null
            };

            await context.Items.AddAsync(@case);
            await context.SaveChangesAsync();

            return Ok(@case.ToCaseDto(new List<ItemResponse>()));
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
            var user = await context.Users.FirstAsync(x => x.Username == User.Identity!.Name);
            if (!user.IsAdmin) return Forbid();

            var @case = await context.Items.FirstOrDefaultAsync(x => x.ItemId == caseId && x.ItemType == ItemType.Case);

            if (@case == null) return NotFound();

            var inventoryItems = await context.Userinventories.Where(x => x.ItemId == @case.ItemId).ToListAsync();

            foreach (var item in inventoryItems)
            {
                context.Userinventories.Remove(item);
            }

            context.Items.Remove(@case);
            await context.SaveChangesAsync();

            return NoContent();
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
            User user = await context.Users.FirstAsync(x => x.Username == User.Identity!.Name);
            if (!user.IsAdmin) return Forbid();

            var @case = await context.Items.FirstOrDefaultAsync(x => x.ItemId == caseId && x.ItemType == ItemType.Case);
            if (@case == null) return NotFound();

            @case.ItemName = details.Name;
            @case.ItemValue = details.Value;
            if (details.AssetUrl != null) @case.ItemAssetUrl = details.AssetUrl;

            await context.SaveChangesAsync();

            var caseItems = await context.CaseItems.Where(x => x.Case == @case).Select(x => x.Item.ToDto()).ToListAsync();

            return Ok(@case.ToCaseDto(caseItems));
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
            User user = await context.Users.FirstAsync(x => x.Username == User.Identity!.Name);
            if (!user.IsAdmin) return Forbid();


            var @case = await context.Items.FirstOrDefaultAsync(x => x.ItemType == ItemType.Case && x.ItemId == caseId);
            var item = await context.Items.FirstOrDefaultAsync(x => x.ItemType == ItemType.Item && x.ItemId == itemId);

            if (@case == null || item == null) return NotFound();

            await context.CaseItems.AddAsync(new CaseItem
            {
                CaseId = @case.ItemId,
                ItemId = item.ItemId
            });
            await context.SaveChangesAsync();

            var caseItems = await context.CaseItems.Where(x => x.Case == @case).Select(x => x.Item.ToDto()).ToListAsync();

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
        public async Task<ActionResult> DeleteCaseItem(int caseId, int itemId)
        {
            User user = await context.Users.FirstAsync(x => x.Username == User.Identity!.Name);
            if (!user.IsAdmin) return Forbid();


            var @case = await context.Items.FindAsync(caseId);
            var item = await context.Items.FindAsync(itemId);
            if (@case == null || item == null) return NotFound();

            var caseItem = await context.CaseItems.FindAsync(caseId, itemId);
            if (caseItem == null) return NotFound();

            context.CaseItems.Remove(caseItem);
            await context.SaveChangesAsync();

            var caseItems = await context.CaseItems.Where(x => x.Case == @case).Select(x => x.Item.ToDto()).ToListAsync();

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
        public async Task<ActionResult<CurrentGiveawayResponse>> AddGiveaway(GiveawayRecord details)
        {
            User user = await context.Users.FirstAsync(x => x.Username == User.Identity!.Name);
            if (!user.IsAdmin) return Forbid();

            var item = await context.Items.FindAsync(details.ItemId);
            if (item == null) return NotFound();

            var giveaway = new Giveaway
            {
                ItemId = item.ItemId,
                GiveawayDate = details.Date.ToLocalTime(),
                GiveawayDescription = details.Description,
                GiveawayName = details.Name,
            };

            await context.Giveaways.AddAsync(giveaway);
            await context.SaveChangesAsync();

            return Ok(new CurrentGiveawayResponse
            {
                GiveawayDate = giveaway.GiveawayDate,
                GiveawayDescription = giveaway.GiveawayDescription,
                GiveawayId = giveaway.GiveawayId,
                GiveawayItem = giveaway.Item!.ItemName,
                GiveawayName = giveaway.GiveawayName
            });
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
            var user = await context.Users.FirstAsync(x => x.Username == User.Identity!.Name);
            if (!user.IsAdmin) return Forbid();

            var giveaway = await context.Giveaways.FindAsync(giveawayId);

            if (giveaway == null) return NotFound();

            var participants = await context.Users.Include(x => x.Giveaways).Where(x => x.Giveaways.Contains(giveaway)).ToListAsync();

            foreach (var item in participants)
            {
                item.Giveaways.Remove(giveaway);
            }

            context.Giveaways.Remove(giveaway);

            await context.SaveChangesAsync();

            return NoContent();
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
        [ProducesResponseType(typeof(CurrentGiveawayResponse), StatusCodes.Status200OK)]
        [ProducesResponseType(typeof(void), StatusCodes.Status403Forbidden)]
        [ProducesResponseType(typeof(void), StatusCodes.Status404NotFound)]
        [ProducesResponseType(typeof(void), StatusCodes.Status401Unauthorized)]
        [ProducesResponseType(typeof(void), StatusCodes.Status409Conflict)]
        [ProducesResponseType(typeof(void), StatusCodes.Status400BadRequest)]
        [Authorize]
        public async Task<ActionResult<CurrentGiveawayResponse>> UpdateGiveaway(int giveawayId, GiveawayRecord details)
        {
            User user = await context.Users.FirstAsync(x => x.Username == User.Identity!.Name);
            if (!user.IsAdmin) return Forbid();

            var giveaway = await context.Giveaways.FindAsync(giveawayId);
            if (giveaway == null) return NotFound();
            if (giveaway.GiveawayDate < DateTime.Now) return Conflict();
            if (details.Date < DateTime.Now) return BadRequest();

            var item = await context.Items.FindAsync(details.ItemId);
            if (item == null) return NotFound();

            giveaway.GiveawayDate = details.Date.ToLocalTime();
            giveaway.GiveawayDescription = details.Description;
            giveaway.GiveawayName = details.Name;
            giveaway.ItemId = item.ItemId;

            await context.SaveChangesAsync();

            return Ok(new CurrentGiveawayResponse
            {
                GiveawayDate = giveaway.GiveawayDate,
                GiveawayDescription = giveaway.GiveawayDescription,
                GiveawayId = giveaway.GiveawayId,
                GiveawayItem = giveaway.Item!.ItemName,
                GiveawayName = giveaway.GiveawayName
            });
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
            User user = await context.Users.FirstAsync(x => x.Username == User.Identity!.Name);
            if (!user.IsAdmin) return Forbid();


            Item item = new()
            {
                ItemType = ItemType.Item,
                ItemName = details.Name,
                ItemDescription = details.Description,
                ItemRarity = details.Rarity,
                ItemSkinName = details.SkinName,
                ItemValue = details.Value,
                ItemAssetUrl = details.AssetUrl ?? null
            };

            await context.Items.AddAsync(item);
            await context.SaveChangesAsync();

            return Ok(item.ToDto());
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
            User user = await context.Users.FirstAsync(x => x.Username == User.Identity!.Name);
            if (!user.IsAdmin) return Forbid();

            var item = await context.Items.FirstOrDefaultAsync(x => x.ItemId == itemId && x.ItemType == ItemType.Item);

            if (item == null) return NotFound();

            var inventories = await context.Userinventories.Where(x => x.ItemId == itemId).ToListAsync();

            foreach (var inventoryItem in inventories)
            {
                context.Userinventories.Remove(inventoryItem);
            }

            return NoContent();
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
            User user = await context.Users.FirstAsync(x => x.Username == User.Identity!.Name);
            if (!user.IsAdmin) return Forbid();

            var users = await context.Users.ToListAsync();

            var userDtos = new List<UserResponse>();

            foreach (var u in users)
            {
                var items = await context.Userinventories.Where(x => x.UserId == u.UserId).Select(x => x.Item.ToDto()).ToListAsync();
                userDtos.Add(u.ToDto(items));
            }

            return Ok(userDtos);
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
        [ProducesResponseType(typeof(UserResponse), StatusCodes.Status200OK)]
        [ProducesResponseType(typeof(void), StatusCodes.Status403Forbidden)]
        [ProducesResponseType(typeof(void), StatusCodes.Status404NotFound)]
        [ProducesResponseType(typeof(void), StatusCodes.Status401Unauthorized)]
        [ProducesResponseType(typeof(ActionResult), StatusCodes.Status409Conflict)]
        [Authorize]
        public async Task<ActionResult<UserResponse>> UpdateUser(int userId, UserEditRecord details)
        {
            User user = await context.Users.FirstAsync(x => x.Username == User.Identity!.Name);
            if (!user.IsAdmin) return Forbid();

            var target = await context.Users.FirstOrDefaultAsync(x => x.UserId == userId);
            if (target == null) return NotFound();

            if (await context.Users.AnyAsync(x => x.Username == details.Username && x.UserId != userId)) return Conflict(new { Status = "ERR", Message = "A megadott felhasználónév már foglalt." });
            if (await context.Users.AnyAsync(x => x.Email == details.Email && x.UserId != userId)) return Conflict(new { Status = "ERR", Message = "Az megadott e-mail már használatban van." });

            target.Username = details.Username;
            target.Email = details.Email;
            target.Balance = details.Balance;

            await context.SaveChangesAsync();

            var items = await context.Userinventories.Where(x => x.UserId == target.UserId).Select(x => x.Item.ToDto()).ToListAsync();
            return Ok(target.ToDto(items));
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
            User user = await context.Users.FirstAsync(x => x.Username == User.Identity!.Name);
            if (!user.IsAdmin) return Forbid();

            var target = await context.Users.FirstOrDefaultAsync(x => x.UserId == userId);
            var item = await context.Items.FirstOrDefaultAsync(x => x.ItemId == itemId && x.ItemType == ItemType.Item);
            if (target == null || item == null) return NotFound();

            await context.Userinventories.AddAsync(new Userinventory
            {
                UserId = target.UserId,
                ItemId = item.ItemId
            });
            await context.SaveChangesAsync();

            List<InventoryItemResponse> items = await context.Userinventories.Where(x => x.UserId == user.UserId)
                .Select(x => x.Item.ToInventoryItemDto(x.InventoryId))
                .ToListAsync();

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
        [Route("admin/users/{userId:int}/inventory/{itemId:int}")]
        [Authorize]
        public async Task<ActionResult> DeleteInventoryItem(int userId, int itemId)
        {
            User user = await context.Users.FirstAsync(x => x.Username == User.Identity!.Name);
            if (!user.IsAdmin) return Forbid();

            var target = await context.Users.FirstOrDefaultAsync(x => x.UserId == userId);
            var item = await context.Items.FirstOrDefaultAsync(x => x.ItemId == itemId && x.ItemType == ItemType.Item);
            if (target == null || item == null) return NotFound();

            var userInventory = await context.Userinventories.FirstOrDefaultAsync(x => x.UserId == target.UserId && x.ItemId == item.ItemId);
            if (userInventory == null) return NotFound();

            context.Userinventories.Remove(userInventory);
            await context.SaveChangesAsync();

            List<InventoryItemResponse> items = await context.Userinventories.Where(x => x.UserId == user.UserId).Select(x => x.Item.ToInventoryItemDto(x.InventoryId)).ToListAsync();

            return Ok(items);
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
            User user = await context.Users.FirstAsync(x => x.Username == User.Identity!.Name);
            if (!user.IsAdmin) return Forbid();

            var item = await context.Items.FirstOrDefaultAsync(x => x.ItemId == itemId && x.ItemType == ItemType.Item);
            if (item == null) return NotFound();

            item.ItemName = details.Name;
            item.ItemDescription = details.Description;
            item.ItemRarity = details.Rarity;
            item.ItemSkinName = details.SkinName;
            item.ItemValue = details.Value;
            if (details.AssetUrl != null) item.ItemAssetUrl = details.AssetUrl;

            await context.SaveChangesAsync();

            return Ok(item.ToDto());
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
            var user = await context.Users.FirstAsync(x => x.Username == User.Identity!.Name);
            if (!user.IsAdmin) return Forbid();

            try
            {
                if (image.Length == 0)
                {
                    return BadRequest(new ActionStatus { Status = "ERR", Message = "Nincs megadva kép." });
                }

                var allowedExtensions = new[] { ".jpg", ".jpeg", ".jpeg2000", ".png", ".gif" };
                var extension = Path.GetExtension(image.FileName).ToLower();

                if (!allowedExtensions.Contains(extension))
                {
                    return BadRequest(new ActionStatus { Status = "ERR", Message = "Nem megfelelő képformátum." });
                }

                using (var reader = new BinaryReader(image.OpenReadStream()))
                {
                    var signatures = _fileSignatures.Values.SelectMany(x => x).ToList();
                    var headerBytes = reader.ReadBytes(_fileSignatures.Max(m => m.Value.Max(n => n.Length)));
                    bool result = signatures.Any(signature => headerBytes.Take(signature.Length).SequenceEqual(signature));
                    
                    if (!result)
                    {
                        return BadRequest(new ActionStatus { Status = "ERR", Message = "Nem megfelelő képformátum." });
                    }
                }

                var fileName = Path.GetRandomFileName() + Path.GetExtension(image.FileName);
                var filePath = Path.Combine("uploads", fileName);

                await using (var stream = new FileStream(filePath, FileMode.Create))
                {
                    await image.CopyToAsync(stream);
                }

                var imageUrl = $"/api/images/{fileName}";

                return Ok(new ActionStatus { Status = "OK", Message = imageUrl });
            }
            catch (Exception ex)
            {
                return StatusCode(500, new ActionStatus { Status = "ERR", Message = ex.Message });
            }
        }

        private static (string accessToken, string refreshToken) GenerateTokens(User user)
        {
            var claims = new List<Claim>
            {
                new("name", user.Username),
                new("email", user.Email)
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

        private static readonly Dictionary<string, List<byte[]>> _fileSignatures = new()
        {
            { ".gif", new List<byte[]> { new byte[] { 0x47, 0x49, 0x46, 0x38 } } },
            { ".png", new List<byte[]> { new byte[] { 0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A } } },
            { ".jpeg", new List<byte[]>
                {
                    new byte[] { 0xFF, 0xD8, 0xFF, 0xE0 },
                    new byte[] { 0xFF, 0xD8, 0xFF, 0xE2 },
                    new byte[] { 0xFF, 0xD8, 0xFF, 0xE3 },
                    new byte[] { 0xFF, 0xD8, 0xFF, 0xEE },
                    new byte[] { 0xFF, 0xD8, 0xFF, 0xDB },
                }
            },
            { ".jpeg2000", new List<byte[]> { new byte[] { 0x00, 0x00, 0x00, 0x0C, 0x6A, 0x50, 0x20, 0x20, 0x0D, 0x0A, 0x87, 0x0A } } },

            { ".jpg", new List<byte[]>
                {
                    new byte[] { 0xFF, 0xD8, 0xFF, 0xE0 },
                    new byte[] { 0xFF, 0xD8, 0xFF, 0xE1 },
                    new byte[] { 0xFF, 0xD8, 0xFF, 0xE8 },
                    new byte[] { 0xFF, 0xD8, 0xFF, 0xEE },
                    new byte[] { 0xFF, 0xD8, 0xFF, 0xDB },
                }
            }
        };

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
            return Ok(new ActionStatus { Status = "OK", Message = accessToken });

        }

        private double GetItemUpgradeSuccessChance(decimal currentValue, Item nextItem)
        {
            var next = context.Items.Find(nextItem.ItemId);

            // Alap esély
            double baseChance = 0.8;

            // Érték szerinti esély
            double valueMultiplier = 0.05 * Math.Abs((double)(next!.ItemValue - currentValue)!) / 10;

            double successChance = Math.Max(0, Math.Min(1, Math.Round(baseChance - valueMultiplier, 2)));

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
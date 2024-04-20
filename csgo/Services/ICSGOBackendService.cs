using csgo.Models;
using static csgo.Dtos;

namespace csgo.Services
{
    /// <summary>
    /// Backend szolgáltatás interfész.
    /// </summary>
    public interface ICsgoBackendService
    {
        /// <summary>
        /// Új felhasználó regisztrálása.
        /// </summary>
        /// <param name="register">Egy "Register" rekord, ami az új felhasználó felhasználónevét, email címét, és jelszavát tartalmazza.</param>
        /// <returns>A "Sikeres regisztráció!" szöveget, vagy hiba esetén a hibaüzenet szövegét.</returns>
        public Task<ActionStatus> RegisterAsync(RegisterRequest register);

        /// <summary>
        /// Egy felhasználó profil adatainak lekérése.
        /// </summary>
        /// <param name="user">A felhasználó.</param>
        /// <returns>A felhasználó felhasználónevét, és a jelenlegi egyenlegét.</returns>
        public Task<ActionStatus> GetProfileAsync(User user);

        /// <summary>
        /// Egy felhasználó leltárában lévő tárgyak lekérése.
        /// </summary>
        /// <param name="user">A felhasználó.</param>
        /// <returns>A felhasználó leltárában lévő tárgyak listáját.</returns>
        public Task<ActionStatus> GetInventoryAsync(User user);

        /// <summary>
        /// Egy meglévő felhasználó bejelentkeztetése.
        /// </summary>
        /// <param name="login">Egy "Login" rekord, ami a felhasználó nevét, és jelszavát tartalmazza, és ha be van kapcsolva, akkor a két faktoros belépés adatait is.</param>
        /// <param name="jsonOptions">A WebAuthn beállítások JSON formátumban. (opcionális)</param>
        /// <returns>Egy új access-refresh token párt.</returns>
        public Task<ActionStatus> LoginUserAsync(LoginRequest login, string? jsonOptions = null);

        /// <summary>
        /// WebAuthn attesztáció
        /// </summary>
        /// <param name="user">A kérelmet küldő felhasználó</param>
        /// <param name="details">A WebAuthn attesztáció lépése. (1. vagy 2. lépés)</param>
        /// <param name="jsonOptions">Az attesztálási opciók JSON formátumban (csak 2. mód esetén)</param>
        /// <returns>A WebAuthn attesztáció beállításait.</returns>
        public Task<ActionStatus> WebAuthnAttestationAsync(User user, WebauthnAttestationRequest details, string? jsonOptions = null);


        /// <summary>
        /// WebAuthn kikapcsolása
        /// </summary>
        /// <returns>A kikapcsolás eredményét.</returns>
        /// <param name="user">A kérelmet küldő felhasználó</param>
        /// <param name="request">WebAuthn kikapcsolási kérelem</param>
        /// <param name="jsonOptions">Az attesztálási opciók JSON formátumban</param>
        public Task<ActionStatus> DisableWebauthnAsync(User user, WebauthnDisableRequest request, string? jsonOptions = null);

        /// <summary>
        /// TOTP kulcs generálása
        /// </summary>
        /// <param name="user">A kérelmet küldő felhasználó</param>
        /// <returns>Egy TOTP kulcsot</returns>
        public Task<ActionStatus> GenerateTotpTokenAsync(User user);

        /// <summary>
        /// TOTP kulcs ellenőrzeése
        /// </summary>
        /// <param name="request">A TOTP kulcs</param>
        /// <param name="user">A kérelmet küldő felhasználó</param>
        /// <returns>Az eredményt, hogy sikeres volt-e a TOTP kulcs ellenőrzése.</returns>
        public Task<ActionStatus> CheckTotpTokenAsync(User user, EnableTOTPRequest request);

        /// <summary>
        /// TOTP kikapcsolása
        /// </summary>
        /// <returns>Az eredményt, hogy sikeres volt-e a TOTP kikapcsolása.</returns>
        /// <param name="request">TOTP kód, jelszó</param>
        /// <param name="user">A kérelmet küldő felhasználó</param>
        public Task<ActionStatus> DisableTotpAsync(User user, DisableTOTPRequest request);

        /// <summary>
        /// Az összes létező láda adatainak lekérdezése.
        /// </summary>
        /// <returns>Egy listát, ami tartalmazza az összes láda adatait.</returns>
        public Task<ActionStatus> GetCasesAsync();

        /// <summary>
        /// Az összes létező tárgy adatainak lekérdezése.
        /// </summary>
        /// <returns>Egy listát, ami tartalmazza az összes tárgy adatait.</returns>
        public Task<ActionStatus> GetItemsAsync();

        /// <summary>
        /// Egy láda kinyitása.
        /// </summary>
        /// <param name="user">A kérelmet küldő felhasználó.</param>
        /// <param name="caseId">A láda azonosítója.</param>
        /// <returns>A ládanyitás eredményét</returns>
        public Task<ActionStatus> OpenCaseAsync(User user, int caseId);

        /// <summary>
        /// Egy tárgy eladása.
        /// </summary>
        /// <param name="user">A kérelmet küldő felhasználó.</param>
        /// <param name="inventoryId">A tárgy leltárazonosítója.</param>
        /// <returns>Az eladás eredményét.</returns>
        public Task<ActionStatus> SellItemAsync(User user, int inventoryId);

        /// <summary>
        /// Egy vagy több tárgy kikérése.
        /// </summary>
        /// <param name="user">A kérelmet küldő felhasználó.</param>
        /// <param name="request">A tárgyak leltárazonosítói.</param>
        /// <returns>A kikérés eredményét.</returns>
        public Task<ActionStatus> WithdrawItemsAsync(User user, ItemWithdrawRequest request);

        /// <summary>
        /// Egyenleg feltöltése.
        /// </summary>
        /// <param name="user">A kérelmet küldő felhasználó.</param>
        /// <param name="amount">A feltöltendő összeg.</param> 
        /// <returns>A feltöltés eredményét.</returns>
        public Task<ActionStatus> DepositAsync(User user, double amount);
        
        /// <summary>
        /// Visszaad egy listát, ami azt tartalmazza hogy melyik tárgyakra lehet továbbfejleszteni a megadott tárgy(akat).
        /// </summary>
        /// <param name="user">A kérelmet küldő felhasználó.</param>
        /// <param name="request">A tárgy(ak) leltárazonosítójai, és a szorzó.</param>
        /// <returns>Egy listát, ami azt tartalmazza hogy melyik tárgyakra lehet továbbfejleszteni a megadott tárgyat.</returns>
        public Task<ActionStatus> GetUpgradeItemsAsync(User user, ItemUpgradeListRequest request);
       
        /// <summary>
        /// Egy tárgy továbbfejlesztése
        /// </summary>
        /// <param name="user">A kérelmet küldő felhasználó.</param>
        /// <param name="request">A tárgy(ak) leltárazonosítójai, a kért tárgy azonosítója, és a szorzó.</param>
        /// <returns>Visszaadja a fejleszett tárgya adatait ha sikerült, különben null.</returns>
        public Task<ActionStatus> UpgradeItemAsync(User user, ItemUpgradeRequest request);

        /// <summary>
        /// Napi jutalom kiváltása.
        /// </summary>
        /// <param name="user">A kérelmet küldő felhasználó.</param>
        /// <returns>A napi jutalom mennyiségét.</returns>
        
        public Task<ActionStatus> ClaimDailyRewardAsync(User user);

        /// <summary>
        /// Csatlakozás egy jelenleg aktív nyereményjátékhoz.
        /// </summary>
        /// <param name="user">A kérelmet küldő felhasználó.</param>
        /// <param name="id">A csatlakozandó nyereményjáték azonosítója.</param>
        /// <returns>A csatlakozás eredményét.</returns>

        public Task<ActionStatus> JoinGiveawayAsync(User user, int id);

        /// <summary>
        /// A közelgő nyereményjátékok adatainak lekérése.
        /// </summary>
        /// <param name="user">A kérelmet küldő felhasználó.</param>
        /// <returns>A közelgő nyereményjátékok adatait.</returns>
        public Task<ActionStatus> GetGiveawaysAsync(User user);

        /// <summary>
        /// A múltbeli nyereményjátékok adatainak lekérése.
        /// </summary>
        /// <returns>A múltbeli nyereményjátékok adatait.</returns>
        public Task<ActionStatus> GetPastGiveawaysAsync();

        /// <summary>
        /// Új láda létrehozása.
        /// </summary>
        /// <param name="details">A láda leírása.</param>
        /// <returns>A láda leírását.</returns>
        public Task<ActionStatus> AddCaseAsync(CaseRecord details);

        /// <summary>
        /// Létező láda törlése
        /// </summary>
        /// <param name="caseId">A láda azonosítója.</param>
        /// <returns>A törlés eredményét.</returns>
        public Task<ActionStatus> DeleteCaseAsync(int caseId);

        /// <summary>
        /// Létező láda módosítása
        /// </summary>
        /// <param name="caseId">A módosítandó láda azonosítója.</param>
        /// <param name="details">A láda új adatai.</param>
        /// <returns>A láda új adatait.</returns>
        public Task<ActionStatus> UpdateCaseAsync(int caseId, CaseRecord details);

        /// <summary>
        /// Hozzáad egy tárgyat egy ládához.
        /// </summary>
        /// <param name="caseId">A módosítandó láda azonosítója.</param>
        /// <param name="itemId">A hozzáadandó tárgy azonosítója.</param>
        /// <returns>A láda frissített adatait.</returns>
        public Task<ActionStatus> AddCaseItemAsync(int caseId, int itemId);

        /// <summary>
        /// Eltávolít egy tárgyat egy ládából.
        /// </summary>
        /// <param name="caseId">A módosítandó láda azonosítója.</param>
        /// <param name="itemId">A eltávolítandó tárgy azonosítója.</param>
        /// <returns>A láda frissített adatait.</returns>
        public Task<ActionStatus> DeleteCaseItemAsync(int caseId, int itemId);

        /// <summary>
        /// Új nyereményjáték létrehozása.
        /// </summary>
        /// <param name="details">A nyereményjáték leírása.</param>
        /// <returns>A nyereményjáték leírását.</returns>
        public Task<ActionStatus> AddGiveawayAsync(GiveawayRecord details);

        /// <summary>
        /// Létező nyeremenyjáték törlése
        /// </summary>
        /// <param name="giveawayId">A nyereményjáték azonosítója.</param>
        /// <returns>A törlés eredményét.</returns>
        public Task<ActionStatus> DeleteGiveawayAsync(int giveawayId);

        /// <summary>
        /// Létező nyereményjáték adatainak módosítása.
        /// </summary>
        /// <param name="giveawayId">A nyereményjáték azonosítója.</param>
        /// <param name="details">A nyereményjáték új adatai.</param>
        /// <returns>A nyereményjáték új adatait.</returns>
        public Task<ActionStatus> UpdateGiveawayAsync(int giveawayId, GiveawayRecord details);

        /// <summary>
        /// Új tárgy létrehozása.
        /// </summary>
        /// <param name="details">A tárgy leírása.</param>
        /// <returns>A tárgy leírását.</returns>
        public Task<ActionStatus> AddItemAsync(ItemRecord details);

        /// <summary>
        /// Egy létező tárgy törlése
        /// </summary>
        /// <param name="itemId">A tárgy azonosítója.</param>
        /// <returns>A törlés eredményét.</returns>
        public Task<ActionStatus> DeleteItemAsync(int itemId);

        /// <summary>
        /// Az összes létező felhasználó adatainak lekérdezése.
        /// </summary>
        /// <returns>Egy listát, ami tartalmazza az összes felhasználó adatait.</returns>
        public Task<ActionStatus> GetUsersAsync();

        /// <summary>
        /// Egy létező felhasználó lekérése felhasználónév alapján.
        /// </summary>
        /// <param name="username">A felhasználó felhasználóneve.</param>
        /// <returns>A felhasználó adatait.</returns>
        public Task<ActionStatus> GetUserAsync(string username);

        /// <summary>
        /// Egy létező felhasználó adatainak módosítása
        /// </summary>
        /// <param name="userId">A felhasználó azonosítója.</param>
        /// <param name="details">A felhasználó új adatai.</param>
        /// <returns>A felhasználó frissített adatait.</returns>
        public Task<ActionStatus> UpdateUserAsync(int userId, UserEditRecord details);

        /// <summary>
        /// Hozzáad egy tárgyat egy felhasználó leltárához.
        /// </summary>
        /// <param name="userId">A felhasználó azonosítója.</param>
        /// <param name="itemId">A hozzáadandó tárgy azonosítója.</param>
        /// <returns>A felhasználó leltárának frissített adatait.</returns>
        public Task<ActionStatus> AddInventoryItemAsync(int userId, int itemId);

        /// <summary>
        /// Eltávolít egy tárgyat egy felhasználó leltárából.
        /// </summary>
        /// <param name="userId">A felhasználó azonosítója.</param>
        /// <param name="itemId">A hozzáadandó tárgy azonosítója.</param>
        /// <returns>A felhasználó leltárának frissített adatait.</returns>
        public Task<ActionStatus> DeleteInventoryItemAsync(int userId, int itemId);

        /// <summary>
        /// Létező tárgy módosítása
        /// </summary>
        /// <param name="itemId">A módosítandó tárgy azonosítója.</param>
        /// <param name="details">A tárgy új adatai.</param>
        /// <returns>A tárgy frissített adatait.</returns>
        public Task<ActionStatus> UpdateItemAsync(int itemId, ItemRecord details);

        /// <summary>
        /// Kép feltöltése
        /// </summary>
        /// <param name="image">A feltöltendő kép.</param>
        /// <returns>A kép elérési útját.</returns>
        public Task<ActionStatus> UploadImageAsync(IFormFile image);

        /// <summary>
        /// Tokenek generálása
        /// </summary>
        /// <param name="user">A felhasználó</param>
        /// <returns>Egy access-refresh token párt</returns>
        public (string accessToken, string refreshToken) GenerateTokens(User user);
    }
}
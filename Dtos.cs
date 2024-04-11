using System.ComponentModel.DataAnnotations;
using System.Runtime.InteropServices;
using System.Text.Json.Serialization;
using Fido2NetLib;
using csgo.Models;

namespace csgo
{
    /// <summary>
    /// DTO osztály
    /// </summary>
    public class Dtos
    {
        /// <summary>
        /// Belépési kérelem
        /// </summary>
        /// <param name="Username">A megadott felhasználónév</param>
        /// <param name="Password">A megadott jelszó</param>
        /// <param name="Mfa">A Kétfaktoros bejelentkezés részletei</param>
        public record LoginRequest([Required] string Username, [Required] string Password, [Optional] MfaOptions? Mfa);

        /// <summary>
        /// Regisztració kérelem
        /// </summary>
        /// <param name="Username">A megadott Felhasználónév</param>
        /// <param name="Email">A megadott Email</param>
        /// <param name="Password">A megadott Jelszó</param>
        public record RegisterRequest([Required] string Username, [Required] string Email, [Required] string Password);

        /// <summary>
        /// TOTP kikapcsolási kérelem
        /// </summary>
        /// <param name="Code">A felhasználótól kért jelenlegi TOTP kód</param>
        /// <param name="Password">A felhasználó jelenlegi jelszava</param>
        public record DisableTOTPRequest([Required] string Code, [Required] string Password);

        /// <summary>
        /// TOTP bekapcsolási kérelem
        /// </summary>
        /// <param name="Code">A felhasználótól kért jelenlegi TOTP kód</param>
        public record EnableTOTPRequest([Required] string Code);

        /// <summary>
        /// Egy tárgy leírása.
        /// </summary>
        /// <param name="Name">A tárgy neve</param>
        /// <param name="Description">A tárgy leírása</param>
        /// <param name="Rarity">A tárgy ritkasága</param>
        /// <param name="SkinName">A tárgy skinének neve</param>
        /// <param name="Value">A tárgy értéke</param>
        /// <param name="AssetUrl">A tárgy képének URL-je</param>
        public record ItemRecord(
            [Required] string Name,
            [Required] string Description,
            [Required] ItemRarity Rarity,
            [Required] string SkinName,
            [Required] decimal Value,
            [Optional] string? AssetUrl);

        /// <summary>
        /// Egy skin leírása.
        /// </summary>
        /// <param name="Name">A skin neve</param>
        /// <param name="Value">A skin értéke</param>
        public record SkinRecord([Required] string Name, [Required] decimal Value);

        /// <summary>
        /// Egy láda leírása
        /// </summary>
        /// <param name="Name">A láda neve</param>
        /// <param name="Value">A láda értéke</param>
        /// <param name="AssetUrl">A láda képének URL-je</param>
        public record CaseRecord([Required] string Name, [Required] decimal Value, [Optional] string? AssetUrl);

        /// <summary>
        /// Egy nyereményjáték leírása
        /// </summary>
        /// <param name="Name">A nyereményjáték neve</param>
        /// <param name="Description">A nyereményjáték leírása</param>
        /// <param name="Date">A nyereményjáték kezdetének ideje</param>
        /// <param name="ItemId">A nyereményjátékban nyerhető tárgy azonosítója</param>
        public record GiveawayRecord([Required] string Name, [Required] string Description, [Required] DateTime Date, [Required] int ItemId);

        /// <summary>
        /// Egy felhasználó leírása (csak módosítható attribútumok)
        /// </summary>
        /// <param name="Username">A felhasználó felhasznaloneve</param>
        /// <param name="Email">A felhasználó email címe</param>
        /// <param name="Balance">A felhasználó egyenlege</param>
        public record UserEditRecord(
            [Required] string Username,
            [Required] string Email,
            [Required] double Balance);
        
        
        /// <summary>
        /// Egy tárgy továbbfejlesztési útjainak lekérdezése
        /// </summary>
        /// <param name="Items">A fejlesztendő tárgy(ak) azonosítója(i)</param>
        /// <param name="Multiplier">A fejlesztéshez használt szorzó</param>
        public record ItemUpgradeListRequest([Required] List<int> Items, [Required] int Multiplier);

        /// <summary>
        /// Egy (vagy több) tárgy kikérése.
        /// </summary>
        /// <param name="Items">A tárgy(ak) leltárazonosítója(i)</param>
        public record ItemWithdrawRequest([Required] List<int> Items);

        /// <summary>
        /// Egy tárgy feljesztési kérelem
        /// </summary>
        /// <param name="Items">A fejlesztendő tárgy(ak) azonosítója(i)</param>
        /// <param name="Multiplier">A fejlesztéshez használt szorzó</param>
        /// <param name="Target">A második tárgy (lehet nulla)</param>
        public record ItemUpgradeRequest([Required] List<int> Items, [Required] int Multiplier, [Required] int Target);

        /// <summary>
        /// WebAuthn attesztáció módok
        /// </summary>
        public enum WebAuthnAttestationMode {
            /// <summary>
            /// Opciók lekérdezése
            /// </summary>
            OPTIONS = 1,

            /// <summary>
            /// Attesztálás
            /// </summary>
            ATTESTATION = 2
        }

        /// <summary>
        /// WebAuthn attesztálási kérelem
        /// </summary>
        /// <param name="Mode">Az attesztálási mód (1. vagy 2.)</param>
        /// <param name="Data">A WebAuthn válasz (csak 2. mód esetén)</param>
        public record WebauthnAttestationRequest([Required] WebAuthnAttestationMode Mode, [Optional] AuthenticatorAttestationRawResponse? Data);

        /// <summary>
        /// Egy állapot üzenet leírása
        /// </summary>
        public record ActionStatus {
            /// <summary>
            /// Állapot
            /// </summary>
            [Required][JsonPropertyName("status")] public string? Status { get; init; }
            /// <summary>
            /// Részletek
            /// </summary>
            [Required][JsonPropertyName("message")] public dynamic? Message { get; init; }
        }

        /// <summary>
        /// Egy tárgy fejlesztésének eredménye (API-kérés értesítése)
        /// </summary>
        public record ItemUpgradeResponse {
            /// <summary>
            /// A fejlesztés eredménye (sikerult-e)
            /// </summary>
            [Required][JsonPropertyName("success")] public bool Success { get; init; }

            /// <summary>
            /// A fejlesztett tárgy (null ha nem sikerült)
            /// </summary>
            [Required][JsonPropertyName("item")] public ItemResponse? Item { get; init; }
        }

        /// <summary>
        /// Egy tárgy leírása (API-kérés válasz)
        /// </summary>
        public record ItemResponse
        {
            /// <summary>
            /// A tárgy azonosítója
            /// </summary>
            [Required][JsonPropertyName("itemId")] public int ItemId { get; init; }

            /// <summary>
            /// A tárgy neve
            /// </summary>
            [Required][JsonPropertyName("itemName")] public string? ItemName { get; init; }

            /// <summary>
            /// A tárgy leírása
            /// </summary>
            [Required][JsonPropertyName("itemDescription")] public string? ItemDescription { get; init; }

            /// <summary>
            /// A tárgy ritkasága
            /// </summary>
            [Required][JsonPropertyName("itemRarity")] public ItemRarity ItemRarity { get; init; }

            /// <summary>
            /// A tárgy skinének neve
            /// </summary>
            [Required][JsonPropertyName("itemSkinName")] public string ItemSkinName { get; init; } = null!;

            /// <summary>
            /// A tárgy értéke
            /// </summary>
            [Required][JsonPropertyName("itemValue")] public decimal ItemValue { get; init; }

            /// <summary>
            /// A tárgy képének URL-je
            /// </summary>
            [Required][JsonPropertyName("itemAssetUrl")] public string? ItemAssetUrl { get; init; }

            /// <summary>
            /// A tárgy típusa
            /// </summary>
            [Required][JsonPropertyName("itemType")] public ItemType ItemType { get; init; }
        }

        /// <summary>
        /// Egy láda leírása (API-kérés válasz)
        /// </summary>
        public record CaseResponse
        {
            /// <summary>
            /// A láda azonosítója
            /// </summary>
            [Required][JsonPropertyName("caseId")] public int ItemId { get; init; }

            /// <summary>
            /// A láda neve
            /// </summary>
            [Required][JsonPropertyName("caseName")] public string? ItemName { get; init; }

            /// <summary>
            /// A láda képének URL-je
            /// </summary>
            [Required][JsonPropertyName("itemAssetUrl")] public string? ItemAssetUrl { get; init; }

            /// <summary>
            /// A láda értéke.
            /// </summary>
            [Required][JsonPropertyName("itemValue")] public decimal ItemValue { get; init; }

            /// <summary>
            /// A láda elemeinek listája
            /// </summary>
            [Required][JsonPropertyName("items")] public List<ItemResponse>? Items { get; init; }
        }

        /// <summary>
        /// Egy felhasználó leírása (API-kérés válasz)
        /// </summary>
        public record UserResponse
        {
            /// <summary>
            /// A felhasználó azonosítója
            /// </summary>
            [Required][JsonPropertyName("userId")] public int Id { get; init; }

            /// <summary>
            /// A felhasználó felhasználoneve
            /// </summary>
            [Required][JsonPropertyName("userName")] public string? Username { get; init; }

            /// <summary>
            /// A felhasználó email címe
            /// </summary>
            [Required][JsonPropertyName("userEmail")] public string? Email { get; init; }

            /// <summary>
            /// A felhasználó egyenlege
            /// </summary>
            [Required][JsonPropertyName("userBalance")] public double Balance { get; init; }

            /// <summary>
            /// A felhasználó bejelentkezési sorozata
            /// </summary>
            [Required][JsonPropertyName("userLoginStreak")] public int LoginStreak { get; init; }

            /// <summary>
            /// Az utolsó időpont, amikor a felhasználó kiváltotta a napi bejelentkezési bónuszát.
            /// </summary>
            [Required][JsonPropertyName("userLastClaimDate")] public DateTime LastClaimDate { get; init; }

            /// <summary>
            /// Megadja, hogy a felhasználónak be van e kapcsolva a TOTP-alapú kétfaktoros bejelentkezés
            /// </summary>
            [Required][JsonPropertyName("userTotpEnabled")] public bool TotpEnabled { get; init; }

            /// <summary>
            /// Megadja, hogy a felhasználónak be van e kapcsolva a WebAuthn-alapú kétfaktoros bejelentkezés
            /// </summary>
            [Required][JsonPropertyName("userWebauthnEnabled")] public bool WebauthnEnabled { get; init; }

            /// <summary>
            /// Megadja, hogy a felhasználó admin e
            /// </summary>
            [Required][JsonPropertyName("userIsAdmin")] public bool IsAdmin { get; init; }

            /// <summary>
            /// A felhasználó leltárában lévő elemek listája.
            /// </summary>
            [Required][JsonPropertyName("userInventoryItems")][JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] public List<ItemResponse>? InventoryItems { get; init; }
        }

        /// <summary>
        /// Egy aktív nyereményjáték leírása (API-kerés válasz)
        /// </summary>
        public record CurrentGiveawayResponse
        {
            /// <summary>
            /// A nyereményjáték azonosítója
            /// </summary>
            [Required][JsonPropertyName("giveawayId")] public int GiveawayId { get; init; }

            /// <summary>
            /// A nyereményjáték neve
            /// </summary>
            [Required][JsonPropertyName("giveawayName")] public string? GiveawayName { get; init; }

            /// <summary>
            /// A nyereményjáték leírása
            /// </summary>
            [Required][JsonPropertyName("giveawayDescription")] public string? GiveawayDescription { get; init; }

            /// <summary>
            /// A nyereményjáték kezdetének ideje
            /// </summary>
            [Required][JsonPropertyName("giveawayDate")] public DateTime GiveawayDate { get; init; }

            /// <summary>
            /// A nyereményjátékban nyerhető tárgy azonosítója
            /// </summary>
            [Required][JsonPropertyName("giveawayItem")] public string? GiveawayItem { get; init; }

            /// <summary>
            /// Megadja, hogy a jelenlegi felhasználó részt vesz e a nyereményjátékban
            /// </summary>
            [Required][JsonPropertyName("giveawayJoined")] public bool GiveawayJoined { get; init; }
        }

        /// <summary>
        /// Egy múltbeli nyereményjáték leírása (API-kerés vélasz)
        /// </summary>
        public record PastGiveawayResponse
        {
            /// <summary>
            /// A nyeremenyjáték azonosítója
            /// </summary>
            [Required][JsonPropertyName("giveawayId")] public int GiveawayId { get; init; }

            /// <summary>
            /// A nyereményjáték neve
            /// </summary>
            [Required][JsonPropertyName("giveawayName")] public string? GiveawayName { get; init; }

            /// <summary>
            /// A nyereményjáték leírása
            /// </summary>
            [Required][JsonPropertyName("giveawayDescription")] public string? GiveawayDescription { get; init; }

            /// <summary>
            /// A nyereményjáték kezdetének ideje
            /// </summary>
            [Required][JsonPropertyName("giveawayItem")] public string? GiveawayItem { get; init; }

            /// <summary>
            /// A nyereményjáték nyertesének neve
            /// </summary>
            [Required][JsonPropertyName("winnerName")] public string? WinnerName { get; init; }

            /// <summary>
            /// A nyereményjáték sorsolásának ideje
            /// </summary>
            [Required][JsonPropertyName("giveawayDate")] public DateTime GiveawayDate { get; init; }
        }

        /// <summary>
        /// Egy leltárban lévő tárgy leírása (API-kérés vélasz)
        /// </summary>
        public record InventoryItemResponse {
            /// <summary>
            /// A leltár azonosítója
            /// </summary>
            [Required][JsonPropertyName("inventoryId")] public int InventoryId { get; init; }

            /// <summary>
            /// A tárgy azonosítója
            /// </summary>
            [Required][JsonPropertyName("itemId")] public int ItemId { get; init; }

            /// <summary>
            /// A tárgy neve
            /// </summary>
            [Required][JsonPropertyName("itemName")] public string? ItemName { get; init; }

            /// <summary>
            /// A tárgy leírása
            /// </summary>
            [Required][JsonPropertyName("itemDescription")] public string? ItemDescription { get; init; }

            /// <summary>
            /// A tárgy ritkasága
            /// </summary>
            [Required][JsonPropertyName("itemRarity")] public ItemRarity ItemRarity { get; init; }

            /// <summary>
            /// A tárgy skinének neve
            /// </summary>
            [Required][JsonPropertyName("itemSkinName")] public string ItemSkinName { get; init; } = null!;

            /// <summary>
            /// A tárgy értéke
            /// </summary>
            [Required][JsonPropertyName("itemValue")] public decimal ItemValue { get; init; }

            /// <summary>
            /// A tárgy képének URL-je
            /// </summary>
            [Required][JsonPropertyName("itemAssetUrl")] public string? ItemAssetUrl { get; init; }

            /// <summary>
            /// A tárgy típusa
            /// </summary>
            [Required][JsonPropertyName("itemType")] public ItemType ItemType { get; init; }
        }
    }
}

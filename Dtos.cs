﻿using System.ComponentModel.DataAnnotations;
using System.Runtime.InteropServices;
using csgo.Models;
using Newtonsoft.Json;

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
        /// Egy tárgy leírása.
        /// </summary>
        /// <param name="Name">A tárgy neve</param>
        /// <param name="Description">A tárgy leírása</param>
        /// <param name="Rarity">A tárgy ritkasága</param>
        /// <param name="SkinName">A tárgy skinének neve</param>
        /// <param name="Value">A tárgy értéke</param>
        public record ItemRecord(
            [Required] string Name,
            [Required] string Description,
            [Required] ItemRarity Rarity,
            [Required] string SkinName,
            [Required] decimal Value);

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
        public record CaseRecord([Required] string Name, [Required] decimal Value);

        /// <summary>
        /// Egy nyereményjáték leírása
        /// </summary>
        /// <param name="Name">A nyereményjáték neve</param>
        /// <param name="Description">A nyereményjáték leírása</param>
        /// <param name="Date">A nyereményjáték kezdetének ideje</param>
        /// <param name="ItemId">A nyereményjátékban nyerhető tárgy azonosítója</param>
        public record GiveawayRecord([Required] string Name, [Required] string Description, [Required] DateTime Date, [Required] int ItemId);

        /// <summary>
        /// Egy állapot üzenet leírása
        /// </summary>
        public record ActionStatus {
            /// <summary>
            /// Állapot
            /// </summary>
            [Required][JsonProperty("status")] public string? Status { get; init; }
            /// <summary>
            /// Részletek
            /// </summary>
            [Required][JsonProperty("message")] public string? Message { get; init; }
        }

        /// <summary>
        /// Egy tárgy leírása (API-kérés válasz)
        /// </summary>
        public record ItemResponse
        {
            /// <summary>
            /// A tárgy azonosítója
            /// </summary>
            [Required][JsonProperty("itemId")] public int ItemId { get; init; }

            /// <summary>
            /// A tárgy neve
            /// </summary>
            [Required][JsonProperty("itemName")] public string? ItemName { get; init; }

            /// <summary>
            /// A tárgy leírása
            /// </summary>
            [Required][JsonProperty("itemDescription")] public string? ItemDescription { get; init; }

            /// <summary>
            /// A tárgy ritkasága
            /// </summary>
            [Required][JsonProperty("itemRarity")] public ItemRarity ItemRarity { get; init; }

            /// <summary>
            /// A tárgy skinének neve
            /// </summary>
            [Required][JsonProperty("itemSkinName")] public string ItemSkinName { get; init; } = null!;

            /// <summary>
            /// A tárgy értéke
            /// </summary>
            [Required][JsonProperty("itemValue")] public decimal ItemValue { get; init; }

            /// <summary>
            /// A tárgy képének URL-je
            /// </summary>
            [Required][JsonProperty("itemAssetUrl")] public string? ItemAssetUrl { get; init; }
        }

        /// <summary>
        /// Egy láda leírása (API-kérés válasz)
        /// </summary>
        public record CaseResponse
        {
            /// <summary>
            /// A láda azonosítója
            /// </summary>
            [Required][JsonProperty("caseId")] public int ItemId { get; init; }

            /// <summary>
            /// A láda neve
            /// </summary>
            [Required][JsonProperty("caseName")] public string? ItemName { get; init; }

            /// <summary>
            /// A láda képének URL-je
            /// </summary>
            [Required][JsonProperty("itemAssetUrl")] public string? ItemAssetUrl { get; init; }

            /// <summary>
            /// A láda értéke.
            /// </summary>
            [Required][JsonProperty("itemValue")] public decimal ItemValue { get; init; }

            /// <summary>
            /// A láda elemeinek listája
            /// </summary>
            [Required][JsonProperty("items")] public List<ItemResponse>? Items { get; init; }
        }

        /// <summary>
        /// Egy felhasználó leírása (API-kérés válasz)
        /// </summary>
        public record UserResponse
        {
            /// <summary>
            /// A felhasználó azonosítója
            /// </summary>
            [Required][JsonProperty("userId")] public int Id { get; init; }

            /// <summary>
            /// A felhasználó felhasználoneve
            /// </summary>
            [Required][JsonProperty("userName")] public string? Username { get; init; }

            /// <summary>
            /// A felhasználó email címe
            /// </summary>
            [Required][JsonProperty("userEmail")] public string? Email { get; init; }

            /// <summary>
            /// A felhasználó egyenlege
            /// </summary>
            [Required][JsonProperty("userBalance")] public double Balance { get; init; }

            /// <summary>
            /// A felhasználó bejelentkezési sorozata
            /// </summary>
            [Required][JsonProperty("userLoginStreak")] public int LoginStreak { get; init; }

            /// <summary>
            /// Megadja, hogy a felhasználónak be van e kapcsolva a TOTP-alapú kétfaktoros bejelentkezés
            /// </summary>
            [Required][JsonProperty("userTotpEnabled")] public bool TotpEnabled { get; init; }

            /// <summary>
            /// Megadja, hogy a felhasználónak be van e kapcsolva a WebAuthn-alapú kétfaktoros bejelentkezés
            /// </summary>
            [Required][JsonProperty("userWebauthnEnabled")] public bool WebauthnEnabled { get; init; }

            /// <summary>
            /// Megadja, hogy a felhasználó admin e
            /// </summary>
            [Required][JsonProperty("userIsAdmin")] public bool IsAdmin { get; init; }

            /// <summary>
            /// A felhasználó leltárában lévő elemek listája.
            /// </summary>
            [Required][JsonProperty("userInventoryItems")] public List<ItemResponse>? InventoryItems { get; init; }
        }

        /// <summary>
        /// Egy felhasználó profiljának leírása (API-kérés válasz)
        /// </summary>
        public record ProfileResponse {
            /// <summary>
            /// A felhasználó felhasználoneve
            /// </summary>
            [Required][JsonProperty("username")] public string? Username { get; init; }
            /// <summary>
            /// A felhasználó jelenlegi egyenlege
            /// </summary>
            [Required][JsonProperty("balance")] public double Balance { get; init; }
        };

        /// <summary>
        /// Egy aktív nyereményjáték leírása (API-kerés válasz)
        /// </summary>
        public record CurrentGiveawayResponse
        {
            /// <summary>
            /// A nyereményjáték azonosítója
            /// </summary>
            [Required][JsonProperty("giveawayId")] public int GiveawayId { get; init; }

            /// <summary>
            /// A nyereményjáték neve
            /// </summary>
            [Required][JsonProperty("giveawayName")] public string? GiveawayName { get; init; }

            /// <summary>
            /// A nyereményjáték leírása
            /// </summary>
            [Required][JsonProperty("giveawayDescription")] public string? GiveawayDescription { get; init; }

            /// <summary>
            /// A nyereményjáték kezdetének ideje
            /// </summary>
            [Required][JsonProperty("giveawayDate")] public DateTime GiveawayDate { get; init; }

            /// <summary>
            /// A nyereményjátékban nyerhető tárgy azonosítója
            /// </summary>
            [Required][JsonProperty("giveawayItem")] public string? GiveawayItem { get; init; }
        }

        /// <summary>
        /// Egy múltbeli nyereményjáték leírása (API-kerés vélasz)
        /// </summary>
        public record PastGiveawayResponse
        {
            /// <summary>
            /// A nyeremenyjáték azonosítója
            /// </summary>
            [Required][JsonProperty("giveawayId")] public int GiveawayId { get; init; }

            /// <summary>
            /// A nyereményjáték neve
            /// </summary>
            [Required][JsonProperty("giveawayName")] public string? GiveawayName { get; init; }

            /// <summary>
            /// A nyereményjáték leírása
            /// </summary>
            [Required][JsonProperty("giveawayDescription")] public string? GiveawayDescription { get; init; }

            /// <summary>
            /// A nyereményjáték kezdetének ideje
            /// </summary>
            [Required][JsonProperty("giveawayItem")] public string? GiveawayItem { get; init; }

            /// <summary>
            /// A nyereményjáték nyertesének neve
            /// </summary>
            [Required][JsonProperty("winnerName")] public string? WinnerName { get; init; }
        }

        /// <summary>
        /// Egy leltárban lévő tárgy leírása (API-kérés vélasz)
        /// </summary>
        public record InventoryItemResponse {
            /// <summary>
            /// A leltár azonosítója
            /// </summary>
            [Required][JsonProperty("inventoryId")] public int InventoryId { get; init; }

            /// <summary>
            /// A tárgy azonosítója
            /// </summary>
            [Required][JsonProperty("itemId")] public int ItemId { get; init; }

            /// <summary>
            /// A tárgy neve
            /// </summary>
            [Required][JsonProperty("itemName")] public string? ItemName { get; init; }

            /// <summary>
            /// A tárgy leírása
            /// </summary>
            [Required][JsonProperty("itemDescription")] public string? ItemDescription { get; init; }

            /// <summary>
            /// A tárgy ritkasága
            /// </summary>
            [Required][JsonProperty("itemRarity")] public ItemRarity ItemRarity { get; init; }

            /// <summary>
            /// A tárgy skinének neve
            /// </summary>
            [Required][JsonProperty("itemSkinName")] public string ItemSkinName { get; init; } = null!;

            /// <summary>
            /// A tárgy értéke
            /// </summary>
            [Required][JsonProperty("itemValue")] public decimal ItemValue { get; init; }

            /// <summary>
            /// A tárgy képének URL-je
            /// </summary>
            [Required][JsonProperty("itemAssetUrl")] public string? ItemAssetUrl { get; init; }
        }
    }
}

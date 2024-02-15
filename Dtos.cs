using System.ComponentModel.DataAnnotations;
using Newtonsoft.Json;

namespace csgo
{
    public class Dtos
    {
        public record Login([Required] string Username, [Required] string Password, MfaOptions? Mfa);

        public record Register([Required] string Username, [Required] string Email, [Required] string Password);

        public record Item(
            [Required] string Name,
            [Required] string Description,
            [Required] int Rarity,
            [Required] int SkinId,
            [Required] decimal Value);

        public record Skin([Required] string Name, [Required] decimal Value);

        public record Case([Required] string Name);

        public record ItemResponse
        {
            [Required] [JsonProperty("itemId")] public int Id { get; init; }

            [Required] [JsonProperty("itemName")] public string? Name { get; init; }

            [Required]
            [JsonProperty("itemDescription")]
            public string? Description { get; init; }

            [Required]
            [JsonProperty("itemRarity")]
            public int Rarity { get; init; }

            [Required]
            [JsonProperty("itemSkinId")]
            public int ItemSkin { get; init; }

            [Required] [JsonProperty("itemValue")] public decimal Value { get; init; }
        }

        public record SkinResponse
        {
            [Required] [JsonProperty("skinId")] public int Id { get; init; }

            [Required] [JsonProperty("skinName")] public string? Name { get; init; }

            [Required] [JsonProperty("skinValue")] public decimal Value { get; init; }
        }

        public record CaseResponse
        {
            [Required] [JsonProperty("caseId")] public int Id { get; init; }

            [Required] [JsonProperty("caseName")] public string? Name { get; init; }

            [Required] [JsonProperty("items")] public List<Models.Item>? Items { get; init; }
        }

        public record UserResponse
        {
            [Required] [JsonProperty("userId")] public int Id { get; init; }

            [Required] [JsonProperty("userName")] public string? Username { get; init; }

            [Required] [JsonProperty("userEmail")] public string? Email { get; init; }

            [Required]
            [JsonProperty("userBalance")]
            public double Balance { get; init; }

            [Required]
            [JsonProperty("userLoginStreak")]
            public int LoginStreak { get; init; }

            [Required]
            [JsonProperty("userTotpEnabled")]
            public bool TotpEnabled { get; init; }

            [Required]
            [JsonProperty("userWebauthnEnabled")]
            public bool WebauthnEnabled { get; init; }

            [Required]
            [JsonProperty("userIsAdmin")]
            public bool IsAdmin { get; init; }

            [Required]
            [JsonProperty("userInventoryItems")]
            public List<Models.Item>? InventoryItems { get; init; }
        }

        public record CurrentGiveawayResponse
        {
            [Required]
            [JsonProperty("giveawayId")]
            public int GiveawayId { get; init; }

            [Required]
            [JsonProperty("giveawayName")]
            public string? GiveawayName { get; init; }

            [Required]
            [JsonProperty("giveawayDescription")]
            public string? GiveawayDescription { get; init; }

            [Required]
            [JsonProperty("giveawayDate")]
            public DateOnly GiveawayDate { get; init; }

            [Required]
            [JsonProperty("giveawayItem")]
            public string? GiveawayItem { get; init; }
        }

        public record PastGiveawayResponse
        {
            [Required]
            [JsonProperty("giveawayId")]
            public int GiveawayId { get; init; }

            [Required]
            [JsonProperty("giveawayName")]
            public string? GiveawayName { get; init; }

            [Required]
            [JsonProperty("giveawayDescription")]
            public string? GiveawayDescription { get; init; }

            [Required]
            [JsonProperty("giveawayItem")]
            public string? GiveawayItem { get; init; }

            [Required]
            [JsonProperty("winnerName")]
            public string? WinnerName { get; init; }
        }

    }
}
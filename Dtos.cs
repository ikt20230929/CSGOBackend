using System.ComponentModel.DataAnnotations;
using Newtonsoft.Json;

namespace csgo
{
    public class Dtos
    {
        public record Login([Required] string Username, [Required] string Password, MfaOptions? Mfa);

        public record Register([Required] string Username, [Required] string Email, [Required] string Password);

        public record Item([Required] string Name, [Required] string Description, [Required] int Rarity,
            [Required] int SkinId, [Required] decimal Value);

        public record Skin([Required] string Name, [Required] decimal Value);

        public record Case([Required] string Name);

        public record ItemResponse(
            [Required] [property: JsonProperty("itemId")] int Id,
            [Required] [property: JsonProperty("itemName")] string Name,
            [Required] [property: JsonProperty("itemDescription")] string Description,
            [Required] [property: JsonProperty("itemRarity")] int Rarity,
            [Required] [property: JsonProperty("itemSkinId")] int Skin,
            [Required] [property: JsonProperty("itemValue")] decimal Value
        );

        public record SkinResponse(
            [Required] [property: JsonProperty("skinId")] int Id,
            [Required] [property: JsonProperty("skinName")] string Name,
            [Required] [property: JsonProperty("skinValue")] decimal Value
        );

        public record CaseResponse(
            [Required] [property: JsonProperty("caseId")] int Id,
            [Required] [property: JsonProperty("caseName")] string Name,
            [Required] [property: JsonProperty("items")] List<Models.Item> Items);

        public record UserResponse(
            [Required] [property: JsonProperty("userId")] int Id,
            [Required] [property: JsonProperty("userName")] string Username,
            [Required] [property: JsonProperty("userEmail")] string Email,
            [Required] [property: JsonProperty("userBalance")] double Balance,
            [Required] [property: JsonProperty("userLoginStreak")] int LoginStreak,
            [Required] [property: JsonProperty("userTotpEnabled")] bool TotpEnabled,
            [Required] [property: JsonProperty("userWebauthnEnabled")] bool WebauthnEnabled,
            [Required] [property: JsonProperty("userIsAdmin")] bool IsAdmin,
            [Required] [property: JsonProperty("userInventoryItems")] List<Models.Item> InventoryItems);
        public record CaseItem([Required] int CaseId, [Required] int ItemId);
    }
}
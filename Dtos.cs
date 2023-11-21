using System.ComponentModel.DataAnnotations;
using csgo.Models;
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
    }
}
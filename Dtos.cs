using System.ComponentModel.DataAnnotations;
using csgo.Models;

namespace csgo
{
    public class Dtos
    {
        public record Login([Required] string Username, [Required] string Password, MfaOptions? Mfa);
        public record Register([Required] string Username, [Required] string Email, [Required] string Password);
        public record AddItem([Required] string Name, [Required] string Description, [Required] int Rarity,
            [Required] int Skin, [Required] decimal Value);
        public record AddSkin([Required] string Name, [Required] decimal Value);

    }
}

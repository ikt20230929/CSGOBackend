using System.ComponentModel.DataAnnotations;

namespace csgo
{
    public class Dtos
    {
        public record Login([Required] string Username, [Required] string Password, MfaOptions? Mfa);
        public record Register([Required] string Username, [Required] string Email, [Required] string Password);
        public record AddItem([Required] string Name, [Required] int Rarity, [Required] string Password);

    }
}

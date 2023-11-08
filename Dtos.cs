using System.ComponentModel.DataAnnotations;

namespace csgo
{
    public class Dtos
    {
        public record Login([Required] string Username, [Required] string Password);
        public record Register([Required] string Username, [Required] string Email, [Required] string Password);
    }
}

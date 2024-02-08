using System.Text;
using Microsoft.IdentityModel.Tokens;

namespace csgo
{
    public class Signing
    {
        public static readonly SymmetricSecurityKey AccessTokenKey = new(Encoding.UTF8.GetBytes(Globals.Config.Jwt.AccessTokenKey));
        public static readonly SigningCredentials AccessTokenCreds = new(AccessTokenKey, SecurityAlgorithms.HmacSha256);
        public static readonly SigningCredentials RefreshTokenCreds = new(new SymmetricSecurityKey(Encoding.UTF8.GetBytes(Globals.Config.Jwt.RefreshTokenKey)), SecurityAlgorithms.HmacSha256);
    }
}

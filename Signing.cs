using System.Text;
using Microsoft.IdentityModel.Tokens;

namespace csgo
{
    public class Signing
    {
        // TODO: HARDCODING THESE IS VERY BAD DO NOT DO THIS

        public static readonly SymmetricSecurityKey AccessTokenKey = new(Encoding.UTF8.GetBytes("OSKEUusjd83waoKS91siak3n391ksOAI"));
        public static readonly SigningCredentials AccessTokenCreds = new(AccessTokenKey, SecurityAlgorithms.HmacSha256);
        public static readonly SigningCredentials RefreshTokenCreds = new(new SymmetricSecurityKey(Encoding.UTF8.GetBytes("MAKSue82oqkslaxmuei8A75SC461KS8a")), SecurityAlgorithms.HmacSha256);
    }
}

using System.Text;
using Microsoft.IdentityModel.Tokens;

namespace csgo
{
    /// <summary>
    /// Aláíró kulcsok
    /// </summary>
    public class Signing
    {
        /// <summary>
        /// Access token aláíró kulcsa
        /// </summary>
        public static readonly SymmetricSecurityKey AccessTokenKey = new(Encoding.UTF8.GetBytes(Globals.Config.Jwt.AccessTokenKey));

        /// <summary>
        /// Access token alaírást hitelesítő adatok
        /// </summary>
        public static readonly SigningCredentials AccessTokenCreds = new(AccessTokenKey, SecurityAlgorithms.HmacSha256);

        /// <summary>
        /// Refresh token aláírást hitelesítő adatok
        /// </summary>
        public static readonly SigningCredentials RefreshTokenCreds = new(new SymmetricSecurityKey(Encoding.UTF8.GetBytes(Globals.Config.Jwt.RefreshTokenKey)), SecurityAlgorithms.HmacSha256);
    }
}

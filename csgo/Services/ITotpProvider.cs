using OtpNet;

namespace csgo.Services
{

    /// <summary>
    /// TOTP interfész
    /// </summary>
    public interface ITotpProvider
    {
        /// <summary>
        /// TOTP kód ellenőrzése
        /// <param name="secret">Titkos kulcs</param>
        /// <param name="totp">TOTP kód</param>
        /// </summary>
        bool VerifyTotp(byte[] secret, string totp);
    }
}
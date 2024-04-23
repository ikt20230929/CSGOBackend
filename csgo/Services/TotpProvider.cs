using OtpNet;

namespace csgo.Services
{
    /// <summary>
    /// TOTP szolgáltatás
    /// </summary>
    public class TotpProvider : ITotpProvider
    {
        /// <summary>
        /// TOTP kód ellenőrzése
        /// <param name="secret">Titkos kulcs</param>
        /// <param name="totp">TOTP kód</param>
        /// </summary>
        public bool VerifyTotp(byte[] secret, string totp)
        {
            return new Totp(secret).VerifyTotp(totp, out _, VerificationWindow.RfcSpecifiedNetworkDelay);
        }
    }
}
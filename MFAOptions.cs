namespace csgo
{
    /// <summary>
    /// Két faktoros belépés típusa
    /// </summary>
    public enum MfaType
    {
        /// <summary>
        /// TOTP
        /// </summary>
        Totp = 1,

        /// <summary>
        /// WebAuthn
        /// </summary>
        WebAuthn = 2
    }

    /// <summary>
    /// Két faktoros belépés beállításai
    /// </summary>
    public class MfaOptions
    {
        /// <summary>
        /// TOTP jelszó
        /// </summary>
        public string? TotpToken;

        /// <summary>
        /// Két faktoros belépés típusa
        /// </summary>
        public MfaType MfaType;
    }
}
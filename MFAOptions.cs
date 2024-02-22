using System.ComponentModel.DataAnnotations;
using Newtonsoft.Json;

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
        [Required][JsonProperty("totpToken")]
        public string TotpToken { get; set; } = null!;

        /// <summary>
        /// Két faktoros belépés típusa
        /// </summary>
        [Required][JsonProperty("mfaType")]
        public MfaType MfaType { get; set; }
    }
}
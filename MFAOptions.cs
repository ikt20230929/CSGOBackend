using System.ComponentModel.DataAnnotations;
using System.Text.Json.Serialization;
using Fido2NetLib;

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
        /// WebAuthn (első lpéés)
        /// </summary>
        WebAuthnOptions = 2,

        /// <summary>
        /// WebAuthn (második lépés)
        /// </summary>
        WebAuthnAssertion = 3
    }

    /// <summary>
    /// Két faktoros belépés beállításai
    /// </summary>
    public class MfaOptions
    {
        /// <summary>
        /// TOTP jelszó
        /// </summary>
        [JsonPropertyName("totpToken")]
        public string? TotpToken { get; set; }

        /// <summary>
        /// WebAuthn attesztáció válasz
        /// </summary>
        [JsonPropertyName("webAuthnAssertionResponse")]
        internal AuthenticatorAssertionRawResponse? WebAuthnAssertationResponse { get; set; }

        /// <summary>
        /// Két faktoros belépés típusa
        /// </summary>
        [Required][JsonPropertyName("mfaType")]
        public MfaType MfaType { get; set; }
    }
}
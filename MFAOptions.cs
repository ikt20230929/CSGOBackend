namespace csgo
{
    public enum MfaType
    {
        Totp = 1,
        WebAuthn = 2
    }
    public class MfaOptions
    {
        public string? TotpToken;
        public MfaType MfaType;
    }
}
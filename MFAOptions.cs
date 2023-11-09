namespace csgo
{
    public enum MFAType
    {
        TOTP = 1,
        WebAuthn = 2
    }
    public class MFAOptions
    {
        public string? totpToken;
        public MFAType mfaType;
    }
}
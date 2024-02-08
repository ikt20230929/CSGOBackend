namespace csgo
{
    public class Config
    {
        // Frontend URL
        public string FrontUrl { get; set; } = null!;

        // Backend URL
        public string BackUrl { get; set; } = null!;

        // JWT settings
        public JwtSettings Jwt { get; set; } = new();

        // Connection string
        public string ConnectionString { get; set; } = null!;
    }

    public class JwtSettings
    {
        // Access token key
        public string AccessTokenKey { get; set; } = null!;

        // Refresh token key
        public string RefreshTokenKey { get; set; } = null!;
    }
}
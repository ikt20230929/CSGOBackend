namespace csgo
{
    /// <summary>
    /// Az alkalmazás beállításai
    /// </summary>
    public class Config
    {
        /// <summary>
        /// Frontend URL-címe
        /// </summary>
        public string FrontUrl { get; set; } = null!;

        /// <summary>
        /// Backend URL-címe
        /// </summary>
        public string BackUrl { get; set; } = null!;

        /// <summary>
        /// JWT beállítások
        /// </summary>
        public JwtSettings Jwt { get; set; } = new();

        /// <summary>
        /// Adatbázis csatlakozási karakterlánca
        /// </summary>
        public string ConnectionString { get; set; } = null!;
    }

    /// <summary>
    /// JWT beállítások
    /// </summary>
    public class JwtSettings
    {
        /// <summary>
        /// Access token kulcs
        /// </summary>
        public string AccessTokenKey { get; set; } = null!;

        /// <summary>
        /// Refresh token kulcs
        /// </summary>
        public string RefreshTokenKey { get; set; } = null!;
    }
}
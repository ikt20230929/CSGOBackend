namespace csgo.Services
{
    /// <summary>
    /// Dátum-idő szolgáltatás
    /// </summary>
    public interface IDateTimeProvider
    {
        /// <summary>
        /// Az aktuális dátum-idő lekérdezése
        /// </summary>
        DateTime Now { get; }
    }
}
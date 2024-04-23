namespace csgo.Services
{
    /// <summary>
    /// Dátum-idő szolgáltatás
    /// </summary>
    public class DateTimeProvider : IDateTimeProvider
    {
        /// <summary>
        /// Az aktuális dátum-idő lekérdezése
        /// </summary>
        public DateTime Now => DateTime.Now;
    }
}
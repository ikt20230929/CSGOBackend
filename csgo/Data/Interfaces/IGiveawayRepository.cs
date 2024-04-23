using csgo.Models;

namespace csgo.Data
{
    /// <summary>
    /// Repository réteg a nyereményjátékok kezeléséhez
    /// </summary>
    public interface IGiveawayRepository
    {
        /// <summary>
        /// Egy nyereményjáték lekérdezése azonosító alapján
        /// </summary>
        /// <param name="giveawayId">A nyereményjáték azonosítója</param>
        /// <returns>A nyereményjáték adatait, vagy null-t ha nem található</returns>
        Task<Giveaway?> GetByIdAsync(int giveawayId);

        /// <summary>
        /// Új nyereményjáték hozzáadása
        /// </summary>
        /// <param name="giveaway">A nyereményjáték adatai</param>
        Task AddAsync(Giveaway giveaway);

        /// <summary>
        /// Nyereményjáték adatainak frissítése
        /// </summary>
        /// <param name="giveaway">A nyereményjáték frissített adatai</param>
        Task UpdateAsync(Giveaway giveaway);

        /// <summary>
        /// Nyereményjáték törlése
        /// </summary>
        /// <param name="giveaway">A törlendő nyereményjáték</param>
        Task DeleteAsync(Giveaway giveaway);

        /// <summary>
        /// Egy nyereményjátékhoz tartozó résztvevők lekérdezése
        /// </summary>
        /// <param name="giveaway">A nyereményjáték</param>
        Task<List<User>> GetParticipantsAsync(Giveaway giveaway);

        /// <summary>
        /// Aktuális nyereményjátékok lekérdezése
        /// </summary>
        /// <returns>Az aktuális nyereményjátékok listáját</returns>
        Task<List<Giveaway>> GetCurrentGiveawaysAsync();

        /// <summary>
        /// Lezajlott nyereményjátékok lekérdezése
        /// </summary>
        /// <returns>A lezajlott nyereményjátékok listáját</returns>
        Task<List<Giveaway>> GetPastGiveawaysAsync();
    }
}
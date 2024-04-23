using csgo.Models;

namespace csgo.Data
{
    /// <summary>
    /// Repository réteg a felhasználói leltár elemek kezeléséhez
    /// </summary>
    public interface IUserInventoryRepository
    {
        /// <summary>
        /// Egy leltár elem lekérdezése azonosító alapján
        /// </summary>
        /// <param name="userInventoryId">A leltár elem azonosítója</param>
        /// <returns>A leltár elem adatait, vagy null-t ha nem található</returns>
        Task<Userinventory?> GetById(int userInventoryId);

        /// <summary>
        /// Új leltár elem hozzáadása
        /// </summary>
        /// <param name="userInventory">A leltár elem adatai</param>
        Task AddAsync(Userinventory userInventory);

        /// <summary>
        /// Leltár elem adatainak frissítése
        /// </summary>
        /// <param name="userInventory">A leltár elem frissített adatai</param>
        Task DeleteAsync(Userinventory userInventory);

        /// <summary>
        /// Egy felhasználó leltárának lekérdezése
        /// </summary>
        /// <param name="userId">A felhasználó azonosítója</param>
        /// <returns>A felhasználó leltárának elemeit</returns>
        Task<List<Userinventory>> GetUserInventoryAsync(int userId);

        /// <summary>
        /// Az összes leltár, ami tartalmazza a megadott tárgyat lekérdezése
        /// </summary>
        /// <param name="itemId">A tárgy azonosítója</param>
        /// <returns>Egy listát, ami az összes leltár elemet tartalmazza, ami tartalmazza a megadott tárgyat</returns>
        Task<List<Userinventory>> GetInventoryItemsByItemIdAsync(int itemId);
    }
}
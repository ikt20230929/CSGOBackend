using csgo.Models;

namespace csgo.Data
{
    /// <summary>
    /// Repository réteg a tárgyak kezeléséhez
    /// </summary>
    public interface IItemRepository
    {
        /// <summary>
        /// Egy tárgy lekérdezése azonosító alapján
        /// </summary>
        /// <param name="itemId">A tárgy azonosítója</param>
        /// <returns>A tárgy adatait, vagy null-t ha nem található</returns>
        Task<Item?> GetItemByIdAsync(int itemId);

        /// <summary>
        /// Egy láda lekérdezése azonosító alapján
        /// </summary>
        /// <param name="caseId">A láda azonosítója</param>
        /// <returns>A láda adatait, vagy null-t ha nem található</returns>
        Task<Item?> GetCaseByIdAsync(int caseId);

        /// <summary>
        /// Visszaad egy listát, ami azt tartalmazza hogy melyik tárgyakra lehet továbbfejleszteni a megadott tárgy(ak)at.
        /// </summary>
        /// <param name="totalValue">A tárgyak összértéke</param>
        /// <returns>Egy listát, ami azt tartalmazza hogy melyik tárgyakra lehet továbbfejleszteni a megadott tárgy(ak)at.</returns>
        Task<List<Item>> GetUpgradeItemsAsync(decimal totalValue);

        /// <summary>
        /// Új tárgy hozzáadása
        /// </summary>
        /// <param name="item">A tárgy adatai</param>
        Task AddAsync(Item item);

        /// <summary>
        /// Tárgy adatainak frissítése
        /// </summary>
        /// <param name="item">A tárgy frissített adatai</param>
        Task UpdateAsync(Item item);

        /// <summary>
        /// Tárgy törlése
        /// </summary>
        /// <param name="item">A törlendő tárgy</param>
        Task DeleteAsync(Item item);

        /// <summary>
        /// Az összes tárgy lekérdezése
        /// </summary>
        /// <returns>Egy listát, ami az összes tárgyat tartalmazza</returns>
        Task<List<Item>> GetAllItemsAsync();

        /// <summary>
        /// Az összes láda lekérdezése
        /// </summary>
        /// <returns>Egy listát, ami az összes ládát tartalmazza</returns>
        Task<List<Item>> GetAllCasesAsync();
    }
}
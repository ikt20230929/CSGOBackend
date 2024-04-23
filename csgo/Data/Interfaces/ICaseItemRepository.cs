using csgo.Models;
using static csgo.Dtos;

namespace csgo.Data
{
    /// <summary>
    /// Repository réteg a láda tárgyak kezeléséhez
    /// </summary>
    public interface ICaseItemRepository
    {
        /// <summary>
        /// Tárgy hozzáadása egy ládához
        /// </summary>
        /// <param name="caseItem">A láda-tárgy kapcsolat leírása</param>
        Task AddAsync(CaseItem caseItem);
        
        /// <summary>
        /// Tárgy törlése egy ládából
        /// </summary>
        /// <param name="caseItem">A láda-tárgy kapcsolat leírása</param>
        Task DeleteAsync(CaseItem caseItem);

        /// <summary>
        /// Visszaadja az összes tárgyat egy ládában
        /// </summary>
        /// <param name="caseId">A láda azonosítója</param>
        /// <returns>A láda összes tárgyát</returns>
        Task<List<CaseItem>> GetCaseItemsAsync(int caseId);

        /// <summary>
        /// Visszaad egy ládához tartózó tárgyat
        /// </summary>
        /// <param name="caseId">A láda azonosítója</param>
        /// <param name="itemId">A tárgy azonosítója</param>
        /// <returns>A tárgy adatait, vagy null-t ha nem található</returns>
        Task<CaseItem?> GetCaseItemByIdAsync(int caseId, int itemId);
    }
}
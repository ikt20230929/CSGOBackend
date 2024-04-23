using csgo.Models;
using Microsoft.EntityFrameworkCore;
using static csgo.Dtos;

namespace csgo.Data {
    /// <summary>
    /// Repository réteg a láda tárgyak kezeléséhez
    /// </summary>
    /// <param name="context">Adatbázis kontextus</param>
    public class CaseItemRepository(CsgoContext context) : ICaseItemRepository
    {
        /// <inheritdoc />
        public async Task AddAsync(CaseItem caseItem)
        {
            await context.CaseItems.AddAsync(caseItem);
            await context.SaveChangesAsync();
        }

        /// <inheritdoc />
        public async Task DeleteAsync(CaseItem caseItem)
        {
            context.CaseItems.Remove(caseItem);
            await context.SaveChangesAsync();
        }

        /// <inheritdoc />
        public async Task<CaseItem?> GetCaseItemByIdAsync(int caseId, int itemId)
        {
            return await context.CaseItems.FindAsync(caseId, itemId);
        }

        /// <inheritdoc />
        public async Task<List<CaseItem>> GetCaseItemsAsync(int caseId)
        {
            return await context.CaseItems.Where(x => x.CaseId == caseId).Include(x => x.Item).ToListAsync();
        }
    }
}
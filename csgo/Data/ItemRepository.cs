using csgo.Models;
using Microsoft.EntityFrameworkCore;

namespace csgo.Data {
    /// <summary>
    /// Repository réteg a tárgyak kezeléséhez
    /// </summary>
    /// <param name="context">Adatbázis kontextus</param>
    public class ItemRepository(CsgoContext context) : IItemRepository
    {
        /// <inheritdoc />
        public async Task AddAsync(Item item)
        {
            await context.Items.AddAsync(item);
            await context.SaveChangesAsync();
        }

        /// <inheritdoc />
        public async Task DeleteAsync(Item item)
        {
            context.Items.Remove(item);
            await context.SaveChangesAsync();
        }

        /// <inheritdoc />
        public async Task<List<Item>> GetAllCasesAsync()
        {
            return await context.Items.Where(x => x.ItemType == ItemType.Case).ToListAsync();
        }

        /// <inheritdoc />
        public async Task<List<Item>> GetAllItemsAsync()
        {
            return await context.Items.Where(x => x.ItemType == ItemType.Item).ToListAsync();
        }

        /// <inheritdoc />
        public async Task<Item?> GetCaseByIdAsync(int caseId)
        {
            return await context.Items.Where(x => x.ItemType == ItemType.Case).FirstOrDefaultAsync(x => x.ItemId == caseId);
        }

        /// <inheritdoc />
        public async Task<Item?> GetItemByIdAsync(int itemId)
        {
            return await context.Items.Where(x => x.ItemType == ItemType.Item).FirstOrDefaultAsync(x => x.ItemId == itemId);
        }

        /// <inheritdoc />
        public async Task<List<Item>> GetUpgradeItemsAsync(decimal totalValue)
        {
            return await context.Items.Where(x => x.ItemValue >= totalValue && x.ItemType == ItemType.Item)
                                      .OrderBy(x => x.ItemValue)
                                      .ToListAsync();
        }

        /// <inheritdoc />
        public async Task UpdateAsync(Item item)
        {
            context.Items.Update(item);
            await context.SaveChangesAsync();
        }
    }
}
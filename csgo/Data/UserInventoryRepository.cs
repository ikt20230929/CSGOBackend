using csgo.Models;
using Microsoft.EntityFrameworkCore;

namespace csgo.Data {
    /// <summary>
    /// Repository réteg a felhasználói leltár elemek kezeléséhez
    /// </summary>
    /// <param name="context">Adatbázis kontextus</param>
    public class UserInventoryRepository(CsgoContext context) : IUserInventoryRepository
    {
        /// <inheritdoc />
        public async Task AddAsync(Userinventory userInventory)
        {
            await context.Userinventories.AddAsync(userInventory);
            await context.SaveChangesAsync();
        }

        /// <inheritdoc />
        public async Task DeleteAsync(Userinventory userInventory)
        {
            context.Userinventories.Remove(userInventory);
            await context.SaveChangesAsync();
        }

        /// <inheritdoc />
        public async Task<Userinventory?> GetById(int userInventoryId)
        {
            return await context.Userinventories.FindAsync(userInventoryId);
        }

        /// <inheritdoc />
        public async Task<List<Userinventory>> GetInventoryItemsByItemIdAsync(int itemId)
        {
            return await context.Userinventories.Where(x => x.ItemId == itemId).ToListAsync();
        }

        /// <inheritdoc />
        public async Task<List<Userinventory>> GetUserInventoryAsync(int userId)
        {
            return await context.Userinventories.Where(x => x.UserId == userId).ToListAsync();
        }
    }
}
using csgo.Models;
using csgo.Services;
using Microsoft.EntityFrameworkCore;

namespace csgo.Data {
    /// <summary>
    /// Repository réteg a nyereményjátékok kezeléséhez
    /// </summary>
    /// <param name="context">Adatbázis kontextus</param>
    /// <param name="dateTimeProvider">Dátum-idő szolgáltatás</param>
    public class GiveawayRepository(CsgoContext context, IDateTimeProvider dateTimeProvider) : IGiveawayRepository
    {
        /// <inheritdoc />
        public async Task AddAsync(Giveaway giveaway)
        {
            await context.Giveaways.AddAsync(giveaway);
            await context.SaveChangesAsync();
        }

        /// <inheritdoc />
        public async Task DeleteAsync(Giveaway giveaway)
        {
            context.Giveaways.Remove(giveaway);
            await context.SaveChangesAsync();
        }

        /// <inheritdoc />
        public async Task<Giveaway?> GetByIdAsync(int giveawayId)
        {
            return await context.Giveaways.FindAsync(giveawayId);
        }

        /// <inheritdoc />
        public async Task<List<Giveaway>> GetCurrentGiveawaysAsync()
        {
            return await context.Giveaways.Where(x => x.GiveawayDate > dateTimeProvider.Now)
                                          .Include(x => x.Item)
                                          .Include(x => x.Users)
                                          .ToListAsync();
        }

        /// <inheritdoc />
        public async Task<List<User>> GetParticipantsAsync(Giveaway giveaway)
        {
            return await context.Users.Include(x => x.Giveaways).Where(x => x.Giveaways.Contains(giveaway)).ToListAsync();
        }

        /// <inheritdoc />
        public async Task<List<Giveaway>> GetPastGiveawaysAsync()
        {
            return await context.Giveaways.Where(x => x.GiveawayDate <= dateTimeProvider.Now && x.WinnerUserId != null)
                                          .Include(x => x.Item)
                                          .Include(giveaway => giveaway.WinnerUser)
                                          .ToListAsync();
        }
        
        /// <inheritdoc />
        public async Task UpdateAsync(Giveaway giveaway)
        {
            context.Giveaways.Update(giveaway);
            await context.SaveChangesAsync();
        }
    }
}
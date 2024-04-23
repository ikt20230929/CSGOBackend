using csgo.Models;
using csgo.Services;
using Microsoft.EntityFrameworkCore;
using Quartz;
using Serilog;

namespace csgo.Jobs
{
    /// <summary>
    /// Nyereményjátékok kezeléséért felelős háttérfeladat.
    /// </summary>
    /// <param name="dbContext">Adatbázis kontextus</param>
    /// <param name="dateTimeProvider">Dátum-idő szolgáltatás</param>
    [DisallowConcurrentExecution]
    public class GiveawayJob(CsgoContext dbContext, IDateTimeProvider dateTimeProvider) : IJob
    {
        /// <summary>
        /// Elkezdi a nyereményjátékok figyelését, és a nyertesek kiválasztását.
        /// </summary>
        /// <param name="context">Futási contextus</param>
        /// <returns></returns>
        public Task Execute(IJobExecutionContext context)
        {
            var giveaways = dbContext.Giveaways.Where(g => g.GiveawayDate <= dateTimeProvider.Now && g.WinnerUserId == null).Include(x => x.Users).ToList();
            foreach (var giveaway in giveaways)
            {
                Log.Information($"Executing giveaway: {giveaway.GiveawayName}");
                var participants = giveaway.Users.ToList();
                if (participants.Count <= 0) continue;
                var random = new Random();
                var winner = participants[random.Next(participants.Count)];
                giveaway.WinnerUser = winner;
                dbContext.Userinventories.Add(new Userinventory
                {
                    ItemId = giveaway.ItemId,
                    UserId = winner.UserId
                });

                foreach (var user in participants)
                {
                    giveaway.Users.Remove(user);
                }

                dbContext.SaveChanges();
                
                Log.Information($"Executed giveaway: {giveaway.GiveawayName}, winner: {winner.Username}");
            }

            return Task.CompletedTask;
        }
    }
}
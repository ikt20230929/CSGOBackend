using csgo.Models;
using Microsoft.EntityFrameworkCore;

namespace csgo.Data {
    /// <summary>
    /// Repository réteg a felhasználók kezeléséhez
    /// </summary>
    /// <param name="context">Adatbázis kontextus</param>
    public class UserRepository(CsgoContext context) : IUserRepository
    {
        /// <inheritdoc />
        public async Task AddAsync(User user)
        {
            await context.Users.AddAsync(user);
            await context.SaveChangesAsync();
        }

        /// <inheritdoc />
        public async Task<bool> CredentialIdExistsAsync(string credentialId)
        {
            return await context.Users.AnyAsync(x => x.WebauthnCredentialId == credentialId);
        }

        /// <inheritdoc />
        public async Task<bool> EmailExistsAsync(string email, int? userId = null)
        {
            return await context.Users.AnyAsync(x => x.Email == email && (!userId.HasValue || x.UserId != userId)); 
        }

        /// <inheritdoc />
        public async Task<List<User>> GetAllAsync()
        {
            return await context.Users.ToListAsync();
        }

        /// <inheritdoc />
        public async Task<User?> GetByIdAsync(int userId)
        {
            return await context.Users.FindAsync(userId);
        }

        /// <inheritdoc />
        public async Task<User?> GetByUsernameAsync(string username)
        {
            return await context.Users.FirstOrDefaultAsync(x => x.Username == username);
        }

        /// <inheritdoc />
        public async Task UpdateAsync(User user)
        {
            context.Users.Update(user);
            await context.SaveChangesAsync();
        }

        /// <inheritdoc />
        public async Task<bool> UsernameExistsAsync(string username, int? userId = null)
        {
            return await context.Users.AnyAsync(x => x.Username == username && (!userId.HasValue || x.UserId != userId));
        }
    }
}
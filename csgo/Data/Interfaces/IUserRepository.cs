using csgo.Models;

namespace csgo.Data
{
    /// <summary>
    /// Repository réteg a felhasználók kezeléséhez
    /// </summary>
    public interface IUserRepository
    {
        /// <summary>
        /// Felhasználó lekérdezése felhasználónév alapján
        /// </summary>
        /// <param name="username">A felhasználónév</param>
        /// <returns>A felhasználó adatait, vagy null-t ha nem található</returns>
        Task<User?> GetByUsernameAsync(string username);

        /// <summary>
        /// Felhasználó lekérdezése azonosító alapján
        /// </summary>
        /// <param name="userId">A felhasználó azonosítója</param>
        /// <returns>A felhasználó adatait, vagy null-t ha nem található</returns>
        Task<User?> GetByIdAsync(int userId);

        /// <summary>
        /// Ellenőrzi, hogy létezik-e megadott hitelesítő azonosítóval rendelkező felhasználó
        /// </summary>
        /// <param name="credentialId">A hitelesítő azonosító</param>
        /// <returns>True, ha létezik, egyébként false</returns>
        Task<bool> CredentialIdExistsAsync(string credentialId);

        /// <summary>
        /// Ellenőrzi, hogy létezik-e megadott felhasználónévvel rendelkező felhasználó
        /// </summary>
        /// <param name="username">A felhasználónév</param>
        /// <param name="userId">A felhasználó azonosítója, amelyet kivételezni kell az ellenőrzésből (opcionális)</param>
        /// <returns>True, ha létezik, egyébként false</returns>
        Task<bool> UsernameExistsAsync(string username, int? userId = null);

        /// <summary>
        /// Ellenőrzi, hogy létezik-e megadott email címmel rendelkező felhasználó
        /// </summary>
        /// <param name="email">Az email cím</param>
        /// <param name="userId">A felhasználó azonosítója, amelyet kivételezni kell az ellenőrzésből (opcionális)</param>
        /// <returns>True, ha létezik, egyébként false</returns>
        Task<bool> EmailExistsAsync(string email, int? userId = null);

        /// <summary>
        /// Új felhasználó hozzáadása
        /// </summary>
        /// <param name="user">A felhasználó adatai</param>
        Task AddAsync(User user);

        /// <summary>
        /// Felhasználó adatainak frissítése
        /// </summary>
        /// <param name="user">A felhasználó frissített adatai</param>
        Task UpdateAsync(User user);

        /// <summary>
        /// Az összes felhasználó lekérdezése
        /// </summary>
        /// <returns>Egy listát, ami az összes felhasználó adatait tartalmazza</returns>
        Task<List<User>> GetAllAsync();
    }
}
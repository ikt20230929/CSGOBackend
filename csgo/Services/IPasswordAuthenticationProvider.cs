namespace csgo.Services {
    /// <summary>
    /// Jelszó ellenőrzés és kódolásért felelős szolgáltatás.
    /// </summary>
    public interface IPasswordAuthenticationProvider {
        /// <summary>
        /// Jelszó ellenőrzése
        /// </summary>
        /// <param name="password">A megadott jelszó</param>
        /// <param name="passwordHash">A helyes jelszó kódolt változata</param>
        /// <returns>Igaz, ha a jelszó megegyezik a kódolt jelszóval, egyébként hamis</returns>
        bool VerifyPassword(string password, string passwordHash);

        /// <summary>
        /// Jelszó kódolása
        /// </summary>
        /// <param name="password">A kódolandó jelszó</param>
        /// <returns>A kódolt jelszó</returns>
        string HashPassword(string password);
    }
}
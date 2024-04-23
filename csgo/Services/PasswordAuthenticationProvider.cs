namespace csgo.Services {
    /// <summary>
    /// Jelszó ellenőrzés és kódolásért felelős szolgáltatás.
    /// </summary>
    public class PasswordAuthenticationProvider : IPasswordAuthenticationProvider {
        /// <inheritdoc />
        public bool VerifyPassword(string password, string passwordHash) {
            return BCrypt.Net.BCrypt.Verify(password, passwordHash);
        }

        /// <inheritdoc />
        public string HashPassword(string password) {
            return BCrypt.Net.BCrypt.HashPassword(password);
        }
    }
}
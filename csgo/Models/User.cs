namespace csgo.Models;

/// <summary>
/// Egy felhasználó
/// </summary>
public class User
{
    /// <summary>
    /// A felhasználó azonosítója
    /// </summary>
    public int UserId { get; set; }

    /// <summary>
    /// A felhasználó neve
    /// </summary>
    public string Username { get; set; } = null!;

    /// <summary>
    /// A felhasználó email címe
    /// </summary>
    public string Email { get; set; } = null!;

    /// <summary>
    /// A felhasználó kódolt jelszava
    /// </summary>
    public string PasswordHash { get; set; } = null!;

    /// <summary>
    /// A felhasználó egyenlege
    /// </summary>
    public double Balance { get; set; } = 0.00;

    /// <summary>
    /// A felhasználó bejelentkezési sorozata
    /// </summary>
    public int LoginStreak { get; set; } = 0;

    /// <summary>
    /// Az utolsó időpont, amikor a felhasználó kiváltotta a napi bejelentkezési bónuszát.
    /// </summary>
    public DateTime LastClaimDate { get; set; }

    /// <summary>
    /// Megadja, hogy a felhasználónak be van e kapcsolva a TOTP-alapú kétfaktoros bejelentkezés
    /// </summary>
    public bool TotpEnabled { get; set; } = false;

    /// <summary>
    /// A felhasználó TOTP titkos kulcsa
    /// </summary>
    public string? TotpSecret { get; set; }

    /// <summary>
    /// Megadja, hogy a felhasználónak be van e kapcsolva a WebAuthn-alapú kétfaktoros bejelentkezés
    /// </summary>
    public bool WebauthnEnabled { get; set; } = false;

    /// <summary>
    /// A felhasználó WebAuthn hitelesítő azonosítója
    /// </summary>
    public string? WebauthnCredentialId { get; set; }

    /// <summary>
    /// A felhasználó WebAuthn nyilvános kulcsa
    /// </summary>
    public string? WebauthnPublicKey { get; set; }

    /// <summary>
    /// Megadja, hogy a felhasználó admin e
    /// </summary>
    public bool IsAdmin { get; set; } = false;

    /// <summary>
    /// Azon nyereményjátékok, amelyekben ez a felhasználó részt veszt vett.
    /// </summary>
    public virtual ICollection<Giveaway> Giveaways { get; set; } = new List<Giveaway>();

    /// <summary>
    /// Azon felhasználói leltárak, amelyek ehez a felhasználóhoz kapcsoltak.
    /// </summary>
    public virtual ICollection<Userinventory> Userinventories { get; set; } = new List<Userinventory>();

    /// <summary>
    /// Azon nyereményjátékok, amelyekben ez a felhasználó részt veszt vett (navigációs elem).
    /// </summary>
    public virtual ICollection<Giveaway> GiveawaysNavigation { get; set; } = new List<Giveaway>();
}

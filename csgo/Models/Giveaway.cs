namespace csgo.Models;

/// <summary>
/// Egy nyereményjáték
/// </summary>
public class Giveaway
{
    /// <summary>
    /// A nyereményjáték azonosítója
    /// </summary>
    public int GiveawayId { get; set; }

    /// <summary>
    /// A nyereményjáték neve
    /// </summary>
    public string GiveawayName { get; set; } = null!;

    /// <summary>
    /// A nyereményjáték leírása
    /// </summary>
    public string? GiveawayDescription { get; set; }

    /// <summary>
    /// A nyeremenyjáték nyertesének azonosítója
    /// </summary>
    public int? WinnerUserId { get; set; }

    /// <summary>
    /// A nyeremenyjáték sorsolásának ideje
    /// </summary>
    public DateTime GiveawayDate { get; set; }

    /// <summary>
    /// A nyereményjátékban nyerhető tárgy azonosítója
    /// </summary>
    public int? ItemId { get; set; }

    /// <summary>
    /// A nyereményjátékban nyerhető tárgy
    /// </summary>
    public virtual Item? Item { get; set; }

    /// <summary>
    /// A nyereményjáték nyertese
    /// </summary>
    public virtual User? WinnerUser { get; set; }

    /// <summary>
    /// A nyereményjátékban résztvevő felhasználók
    /// </summary>
    public virtual ICollection<User> Users { get; set; } = new List<User>();
}

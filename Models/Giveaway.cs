namespace csgo.Models;

public class Giveaway
{
    public int GiveawayId { get; set; }

    public string GiveawayName { get; set; } = null!;

    public string? GiveawayDescription { get; set; }

    public int? WinnerUserId { get; set; }

    public DateOnly? GiveawayDate { get; set; }

    public int? ItemId { get; set; }

    public virtual Item? Item { get; set; }

    public virtual User? WinnerUser { get; set; }
}

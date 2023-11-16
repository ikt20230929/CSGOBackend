namespace csgo.Models;

public class Userinventory
{
    public int InventoryId { get; set; }
    public int? UserId { get; set; }

    public int? ItemId { get; set; }

    public int? ItemUpgradedAmount { get; set; }

    public virtual Item? Item { get; set; }

    public virtual User? User { get; set; }
}

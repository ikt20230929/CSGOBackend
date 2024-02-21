namespace csgo.Models;

/// <summary>
/// Egy felhasználói leltár
/// </summary>
public class Userinventory
{
    /// <summary>
    /// A leltár azonosítója
    /// </summary>
    public int InventoryId { get; set; }

    /// <summary>
    /// Azon felhasználó azonosítója, akihez a leltár tartozik
    /// </summary>
    public int? UserId { get; set; }

    /// <summary>
    /// Egy a leltárban lévő elem azonosítója
    /// </summary>
    public int? ItemId { get; set; }

    /// <summary>
    /// Annak a száma, hogy a tárgyat mennyiszer fejlesztették tovább
    /// </summary>
    public int? ItemUpgradedAmount { get; set; }

    /// <summary>
    /// Egy leltárban lévő elem
    /// </summary>
    public virtual Item? Item { get; set; }

    /// <summary>
    /// Azon felhasználó, akihez a leltár tartozik
    /// </summary>
    public virtual User? User { get; set; }
}

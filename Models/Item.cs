namespace csgo.Models;

/// <summary>
/// Egy tárgy
/// </summary>
public class Item
{
    /// <summary>
    /// A tárgy azonosítója
    /// </summary>
    public int ItemId { get; set; }

    /// <summary>
    /// A tárgy neve
    /// </summary>
    public string ItemName { get; set; } = null!;

    /// <summary>
    /// A tárgy leírása
    /// </summary>
    public string? ItemDescription { get; set; }

    /// <summary>
    /// A tárgy típusa
    /// </summary>
    public ItemType ItemType { get; set; }

    /// <summary>
    /// A tárgy ritkasága
    /// </summary>
    public int ItemRarity { get; set; }

    /// <summary>
    /// A tárgy skinének azonosítója
    /// </summary>
    public int? ItemSkinId { get; set; }

    /// <summary>
    /// A tárgy értéke
    /// </summary>
    public decimal ItemValue { get; set; }

    /// <summary>
    /// A tárgy kép URL-je
    /// </summary>
    public string? ItemAssetUrl { get; set; }

    /// <summary>
    /// Azon nyereményjátékok listája, amelyeken meg lehet nyerni ezt a tárgyat
    /// </summary>
    public virtual ICollection<Giveaway> Giveaways { get; set; } = new List<Giveaway>();

    /// <summary>
    /// A tárgy skine
    /// </summary>
    public virtual Skin Skin { get; set; } = null!;

    /// <summary>
    /// Azon felhasználói leltárak, amelyek tartalmazzák ezt a tárgyat
    /// </summary>
    public virtual ICollection<Userinventory> Userinventories { get; set; } = new List<Userinventory>();
}

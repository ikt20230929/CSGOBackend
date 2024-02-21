namespace csgo.Models;
/// <summary>
/// Egy ládához tartozó tárgy
/// </summary>
public class CaseItem
{
    /// <summary>
    /// A tárgyat tartalmazó láda azonosítója
    /// </summary>
    public int CaseId { get; set; }

    /// <summary>
    /// A tárgy azonosítója
    /// </summary>
    public int ItemId { get; set; }

    /// <summary>
    /// A tárgyat tartalmazó láda
    /// </summary>
    public Item Case { get; set; } = null!;

    /// <summary>
    /// A tárgy
    /// </summary>
    public Item Item { get; set; } = null!;
}
namespace csgo.Models;

/// <summary>
/// Egy skin
/// </summary>
public class Skin
{
    /// <summary>
    /// A skin azonosítója
    /// </summary>
    public int SkinId { get; set; }

    /// <summary>
    /// A skin neve
    /// </summary>
    public string SkinName { get; set; } = null!;

    /// <summary>
    /// A skin értéke
    /// </summary>
    public decimal SkinValue { get; set; }

    /// <summary>
    /// Azon tárgyak listája, amelyeken ez a skin található.
    /// </summary>
    public virtual ICollection<Item> Items { get; set; } = new List<Item>();
}

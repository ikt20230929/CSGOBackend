namespace csgo.Models;

public class Skin
{
    public int SkinId { get; set; }

    public string SkinName { get; set; } = null!;

    public decimal SkinValue { get; set; }

    public virtual ICollection<Item> Items { get; set; } = new List<Item>();
}

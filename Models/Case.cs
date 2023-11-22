namespace csgo.Models;

public class Case
{
    public int CaseId { get; set; }

    public string CaseName { get; set; } = null!;

    public virtual ICollection<Item> Items { get; set; } = new List<Item>();
}

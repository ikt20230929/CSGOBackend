namespace csgo.Models;
public class CaseItem
{
    public int CaseId { get; set; }
    public int ItemId { get; set; }

    public Item Case { get; set; }
    public Item Item { get; set; }
}
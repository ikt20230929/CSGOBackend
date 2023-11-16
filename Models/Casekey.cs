namespace csgo.Models;

public class Casekey
{
    public int? CaseId { get; set; }

    public decimal? Price { get; set; }

    public virtual Case? Case { get; set; }
}

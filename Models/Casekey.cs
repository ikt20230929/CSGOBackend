using System;
using System.Collections.Generic;

namespace csgo.Models;

public partial class Casekey
{
    public int? CaseId { get; set; }

    public decimal? Price { get; set; }

    public virtual Case? Case { get; set; }
}

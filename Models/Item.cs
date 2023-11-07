using System;
using System.Collections.Generic;

namespace csgo.Models;

public partial class Item
{
    public int ItemId { get; set; }

    public string ItemName { get; set; } = null!;

    public string? ItemDescription { get; set; }

    public int? Rarity { get; set; }

    public int? SkinId { get; set; }

    public decimal? ItemValue { get; set; }

    public string? ItemImageUrl { get; set; }

    public virtual ICollection<Giveaway> Giveaways { get; set; } = new List<Giveaway>();

    public virtual Skin? Skin { get; set; }

    public virtual ICollection<Userinventory> Userinventories { get; set; } = new List<Userinventory>();
}

using System;
using System.Collections.Generic;

namespace csgo.Models;

public partial class User
{
    public int UserId { get; set; }

    public string Username { get; set; } = null!;

    public string Email { get; set; } = null!;

    public string PasswordHash { get; set; } = null!;

    public double Balance { get; set; } = 0.00;

    public int LoginStreak { get; set; } = 0;

    public bool TotpEnabled { get; set; } = false;

    public string? TotpSecret { get; set; }

    public bool WebauthnEnabled { get; set; } = false;

    public string? WebauthnCredentialId { get; set; }

    public string? WebauthnPublicKey { get; set; }

    public bool IsAdmin { get; set; } = false;

    public virtual ICollection<Giveaway> Giveaways { get; set; } = new List<Giveaway>();

    public virtual ICollection<Userinventory> Userinventories { get; set; } = new List<Userinventory>();
}

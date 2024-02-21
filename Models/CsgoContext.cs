using Microsoft.EntityFrameworkCore;

namespace csgo.Models;

/// <summary>
/// Entity Framework adatbázis kontextus.
/// </summary>
public partial class CsgoContext : DbContext
{
    /// <summary>
    /// Létrehoz egy új adatbázis kontextust.
    /// </summary>
    public CsgoContext()
    {
    }

    /// <summary>
    /// Létrehoz egy új adatbázis kontextust.
    /// </summary>
    /// <param name="options">A kontextus beállításai</param>
    public CsgoContext(DbContextOptions<CsgoContext> options)
        : base(options)
    {
    }

    /// <summary>
    /// Az adatbázisban lévő nyereményjátékok listája
    /// </summary>
    public virtual DbSet<Giveaway> Giveaways { get; set; } = null!;

    /// <summary>
    /// Az adatbázisban levő tárgyak listája
    /// </summary>
    public virtual DbSet<Item> Items { get; set; } = null!;

    /// <summary>
    /// Az adatbázisban lévő skinek listája
    /// </summary>
    public virtual DbSet<Skin> Skins { get; set; } = null!;

    /// <summary>
    /// Az adatbázisban lévő felhasználók listája
    /// </summary>
    public virtual DbSet<User> Users { get; set; } = null!;

    /// <summary>
    /// Az adatbázisban levö felhasználói leltárak listája 
    /// </summary>
    public virtual DbSet<Userinventory> Userinventories { get; set; } = null!;

    /// <summary>
    /// Az adatbázisban levö láda-tárgy párok listája
    /// </summary>
    public virtual DbSet<CaseItem> CaseItems { get; set; } = null!;

    /// <summary>
    /// Az adatbázisban levö láda kulcsok listája
    /// </summary>
    public virtual DbSet<CaseKey> CaseKeys { get; set; } = null!;

    private static readonly int[] Value = [0, 0];

    /// <summary>
    /// A MySQL használatára konfigurálja a kontextust.
    /// </summary>
    /// <param name="optionsBuilder">Az adatbázis beállításai</param>
    protected override void OnConfiguring(DbContextOptionsBuilder optionsBuilder)
            => optionsBuilder.UseMySql(Globals.Config.ConnectionString, ServerVersion.Parse(Globals.Config.ConnectionString));

    /// <summary>
    /// Konfigurálja az adatbázis-kontextus entitásmodelljeit.
    /// </summary>
    /// <param name="modelBuilder">A kontextus beállításai</param>
    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        modelBuilder
            .UseCollation("utf8mb4_hungarian_ci")
            .HasCharSet("utf8mb4");

        modelBuilder.Entity<Giveaway>(entity =>
        {
            entity.HasKey(e => e.GiveawayId).HasName("PRIMARY");

            entity.ToTable("giveaways");

            entity.HasIndex(e => e.ItemId, "item_id");

            entity.HasIndex(e => e.WinnerUserId, "winner_user_id");

            entity.Property(e => e.GiveawayId)
                .HasColumnType("int(11)")
                .HasColumnName("giveaway_id");
            entity.Property(e => e.GiveawayDate).HasColumnName("giveaway_date");
            entity.Property(e => e.GiveawayDescription)
                .HasColumnType("text")
                .HasColumnName("giveaway_description");
            entity.Property(e => e.GiveawayName)
                .HasMaxLength(255)
                .HasColumnName("giveaway_name");
            entity.Property(e => e.ItemId)
                .HasColumnType("int(11)")
                .HasColumnName("item_id");
            entity.Property(e => e.WinnerUserId)
                .HasColumnType("int(11)")
                .HasColumnName("winner_user_id");

            entity.HasOne(d => d.Item).WithMany(p => p.Giveaways)
                .HasForeignKey(d => d.ItemId)
                .HasConstraintName("giveaways_ibfk_2");

            entity.HasOne(d => d.WinnerUser).WithMany(p => p.Giveaways)
                .HasForeignKey(d => d.WinnerUserId)
                .HasConstraintName("giveaways_ibfk_1");
        });

        modelBuilder.Entity<CaseItem>(entity =>
        {
            entity.HasKey(ci => new { ci.CaseId, ci.ItemId }).HasName("PRIMARY");

            entity.ToTable("case_items");

            entity.Property(e => e.CaseId)
                .HasColumnType("int(11)")
                .HasColumnName("case_id");

            entity.Property(e => e.ItemId)
                .HasColumnType("int(11)")
                .HasColumnName("item_id");

            entity.HasOne(ci => ci.Case)
                .WithMany()
                .HasForeignKey(ci => ci.CaseId)
                .HasConstraintName("case_items_ibfk_1");

            entity.HasOne(ci => ci.Item)
                .WithMany()
                .HasForeignKey(ci => ci.ItemId)
                .HasConstraintName("case_items_ibfk_2");
        });

        modelBuilder.Entity<CaseKey>(entity =>
        {
            entity.HasKey(cki => new { cki.CaseId, cki.CaseKeyId }).HasName("PRIMARY");

            entity.ToTable("case_keys");

            entity.Property(e => e.CaseId)
                .HasColumnType("int(11)")
                .HasColumnName("case_id");

            entity.Property(e => e.CaseKeyId)
                .HasColumnType("int(11)")
                .HasColumnName("key_id");

            entity.HasOne(ci => ci.Case)
                .WithMany()
                .HasForeignKey(ci => ci.CaseId)
                .HasConstraintName("FK_case_keys_items");

            entity.HasOne(ci => ci.Key)
                .WithMany()
                .HasForeignKey(ci => ci.CaseKeyId)
                .HasConstraintName("FK_case_keys_items_2");
        });

        modelBuilder.Entity<Item>(entity =>
        {
            entity.HasKey(e => e.ItemId).HasName("PRIMARY");

            entity.ToTable("items");

            entity.HasIndex(e => e.ItemSkinId, "skin_id");

            entity.Property(e => e.ItemId)
                .HasColumnType("int(11)")
                .HasColumnName("item_id");
            entity.Property(e => e.ItemDescription)
                .HasColumnType("text")
                .HasColumnName("item_description");
            entity.Property(e => e.ItemType)
                .HasColumnType("int(11)")
                .HasColumnName("item_type");
            entity.Property(e => e.ItemName)
                .HasMaxLength(255)
                .HasColumnName("item_name");
            entity.Property(e => e.ItemValue)
                .HasPrecision(10, 2)
                .HasColumnName("item_value");
            entity.Property(e => e.ItemRarity)
                .HasColumnType("int(11)")
                .HasColumnName("rarity");
            entity.Property(e => e.ItemSkinId)
                .HasColumnType("int(11)")
                .HasColumnName("skin_id");

            entity.HasOne(d => d.Skin).WithMany(p => p.Items)
                .HasForeignKey(d => d.ItemSkinId)
                .HasConstraintName("items_ibfk_1");
        });

        modelBuilder.Entity<Skin>(entity =>
        {
            entity.HasKey(e => e.SkinId).HasName("PRIMARY");

            entity.ToTable("skins");

            entity.Property(e => e.SkinId)
                .HasColumnType("int(11)")
                .HasColumnName("skin_id");
            entity.Property(e => e.SkinName)
                .HasMaxLength(255)
                .HasColumnName("skin_name");
            entity.Property(e => e.SkinValue)
                .HasPrecision(10, 2)
                .HasColumnName("skin_value");
        });

        modelBuilder.Entity<User>(entity =>
        {
            entity.HasKey(e => e.UserId).HasName("PRIMARY");

            entity.ToTable("users");

            entity.Property(e => e.UserId)
                .HasColumnType("int(11)")
                .HasColumnName("user_id");
            entity.Property(e => e.Balance)
                .HasPrecision(10, 2)
                .HasColumnName("balance");
            entity.Property(e => e.Email)
                .HasMaxLength(255)
                .HasColumnName("email");
            entity.Property(e => e.IsAdmin).HasColumnName("is_admin");
            entity.Property(e => e.LoginStreak)
                .HasColumnType("int(11)")
                .HasColumnName("login_streak");
            entity.Property(e => e.PasswordHash)
                .HasMaxLength(255)
                .HasColumnName("password_hash");
            entity.Property(e => e.TotpEnabled).HasColumnName("totp_enabled");
            entity.Property(e => e.TotpSecret)
                .HasMaxLength(255)
                .HasColumnName("totp_secret");
            entity.Property(e => e.Username)
                .HasMaxLength(255)
                .HasColumnName("username");
            entity.Property(e => e.WebauthnCredentialId)
                .HasMaxLength(255)
                .HasColumnName("webauthn_credential_id");
            entity.Property(e => e.WebauthnEnabled).HasColumnName("webauthn_enabled");
            entity.Property(e => e.WebauthnPublicKey)
                .HasMaxLength(255)
                .HasColumnName("webauthn_public_key");

            entity.HasMany(d => d.GiveawaysNavigation).WithMany(p => p.Users)
                .UsingEntity<Dictionary<string, object>>(
                    "GiveawayUser",
                    r => r.HasOne<Giveaway>().WithMany()
                        .HasForeignKey("GiveawayId")
                        .OnDelete(DeleteBehavior.ClientSetNull)
                        .HasConstraintName("FK_giveaway_users_giveaways"),
                    l => l.HasOne<User>().WithMany()
                        .HasForeignKey("UserId")
                        .OnDelete(DeleteBehavior.ClientSetNull)
                        .HasConstraintName("FK_giveaway_users_users"),
                    j =>
                    {
                        j.HasKey("UserId", "GiveawayId")
                            .HasName("PRIMARY")
                            .HasAnnotation("MySql:IndexPrefixLength", Value);
                        j.ToTable("giveaway_users");
                        j.HasIndex(["GiveawayId"], "FK_giveaway_users_giveaways");
                        j.IndexerProperty<int>("UserId")
                            .HasColumnType("int(11)")
                            .HasColumnName("userID");
                        j.IndexerProperty<int>("GiveawayId")
                            .HasColumnType("int(11)")
                            .HasColumnName("giveawayID");
                    });
        });

        modelBuilder.Entity<Userinventory>(entity =>
        {
            entity.HasKey(e => e.InventoryId).HasName("PRIMARY");

            entity.ToTable("userinventory");

            entity.HasIndex(e => e.ItemId, "item_id");

            entity.HasIndex(e => e.UserId, "user_id");

            entity.Property(e => e.InventoryId)
                .ValueGeneratedNever()
                .HasColumnType("int(11)")
                .HasColumnName("inventory_id");
            entity.Property(e => e.ItemId)
                .HasColumnType("int(11)")
                .HasColumnName("item_id");
            entity.Property(e => e.ItemUpgradedAmount)
                .HasColumnType("int(11)")
                .HasColumnName("item_upgraded_amount");
            entity.Property(e => e.UserId)
                .HasColumnType("int(11)")
                .HasColumnName("user_id");

            entity.HasOne(d => d.Item).WithMany(p => p.Userinventories)
                .HasForeignKey(d => d.ItemId)
                .HasConstraintName("userinventory_ibfk_2");

            entity.HasOne(d => d.User).WithMany(p => p.Userinventories)
                .HasForeignKey(d => d.UserId)
                .HasConstraintName("userinventory_ibfk_1");
        });

        OnModelCreatingPartial(modelBuilder);
    }

    partial void OnModelCreatingPartial(ModelBuilder modelBuilder);
}

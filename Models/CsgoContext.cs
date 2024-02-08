using Microsoft.EntityFrameworkCore;

namespace csgo.Models;

public partial class CsgoContext : DbContext
{
    public CsgoContext()
    {
    }

    public CsgoContext(DbContextOptions<CsgoContext> options)
        : base(options)
    {
    }

    public virtual DbSet<Case> Cases { get; set; } = null!;

    public virtual DbSet<Casekey> Casekeys { get; set; } = null!;

    public virtual DbSet<Giveaway> Giveaways { get; set; } = null!;

    public virtual DbSet<Item> Items { get; set; } = null!;

    public virtual DbSet<Skin> Skins { get; set; } = null!;

    public virtual DbSet<User> Users { get; set; } = null!;

    public virtual DbSet<Userinventory> Userinventories { get; set; } = null!;

    private static readonly int[] Value = [0, 0];

    protected override void OnConfiguring(DbContextOptionsBuilder optionsBuilder)
        => optionsBuilder.UseMySql(Globals.Config.ConnectionString, ServerVersion.Parse(Globals.Config.ConnectionString));

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        modelBuilder
            .UseCollation("utf8mb4_hungarian_ci")
            .HasCharSet("utf8mb4");

        modelBuilder.Entity<Case>(entity =>
        {
            entity.HasKey(e => e.CaseId).HasName("PRIMARY");

            entity.ToTable("cases");

            entity.Property(e => e.CaseId)
                .HasColumnType("int(11)")
                .HasColumnName("case_id");
            entity.Property(e => e.CaseName)
                .HasMaxLength(255)
                .HasColumnName("case_name");

            entity.HasMany(d => d.Items).WithMany(p => p.Cases)
                .UsingEntity<Dictionary<string, object>>(
                    "CaseItem",
                    r => r.HasOne<Item>().WithMany()
                        .HasForeignKey("ItemId")
                        .OnDelete(DeleteBehavior.ClientSetNull)
                        .HasConstraintName("case_items_ibfk_2"),
                    l => l.HasOne<Case>().WithMany()
                        .HasForeignKey("CaseId")
                        .OnDelete(DeleteBehavior.ClientSetNull)
                        .HasConstraintName("case_items_ibfk_1"),
                    j =>
                    {
                        j.HasKey("CaseId", "ItemId")
                            .HasName("PRIMARY")
                            .HasAnnotation("MySql:IndexPrefixLength", Value);
                        j.ToTable("case_items");
                        j.HasIndex(["ItemId"], "item_id");
                        j.IndexerProperty<int>("CaseId")
                            .HasColumnType("int(11)")
                            .HasColumnName("case_id");
                        j.IndexerProperty<int>("ItemId")
                            .HasColumnType("int(11)")
                            .HasColumnName("item_id");
                    });
        });

        modelBuilder.Entity<Casekey>(entity =>
        {
            entity
                .HasNoKey()
                .ToTable("casekeys");

            entity.HasIndex(e => e.CaseId, "case_id");

            entity.Property(e => e.CaseId)
                .HasColumnType("int(11)")
                .HasColumnName("case_id");
            entity.Property(e => e.Price)
                .HasPrecision(10, 2)
                .HasDefaultValueSql("'0.00'")
                .HasColumnName("price");

            entity.HasOne(d => d.Case).WithMany()
                .HasForeignKey(d => d.CaseId)
                .HasConstraintName("casekeys_ibfk_1");
        });

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

        modelBuilder.Entity<Item>(entity =>
        {
            entity.HasKey(e => e.ItemId).HasName("PRIMARY");

            entity.ToTable("items");

            entity.HasIndex(e => e.SkinId, "skin_id");

            entity.Property(e => e.ItemId)
                .HasColumnType("int(11)")
                .HasColumnName("item_id");
            entity.Property(e => e.ItemDescription)
                .HasColumnType("text")
                .HasColumnName("item_description");
            entity.Property(e => e.ItemName)
                .HasMaxLength(255)
                .HasColumnName("item_name");
            entity.Property(e => e.ItemValue)
                .HasPrecision(10, 2)
                .HasColumnName("item_value");
            entity.Property(e => e.Rarity)
                .HasColumnType("int(11)")
                .HasColumnName("rarity");
            entity.Property(e => e.SkinId)
                .HasColumnType("int(11)")
                .HasColumnName("skin_id");

            entity.HasOne(d => d.Skin).WithMany(p => p.Items)
                .HasForeignKey(d => d.SkinId)
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

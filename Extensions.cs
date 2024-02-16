using csgo.Models;
namespace csgo
{
    public static class Extensions
    {
        public static Dtos.SkinResponse ToDto(this Skin skin)
        {
            return new Dtos.SkinResponse
            {
                SkinId = skin.SkinId,
                SkinName = skin.SkinName,
                SkinValue = skin.SkinValue
            };
        }

        public static Dtos.ItemResponse ToDto(this Item item)
        {
          return new Dtos.ItemResponse
          {
              ItemName = item.ItemName,
              ItemDescription = item.ItemDescription,
              ItemId = item.ItemId,
              ItemRarity = item.ItemRarity,
              ItemSkin = (int)item.ItemSkinId!,
              ItemValue = item.ItemValue
          };
        }

        public static Dtos.CaseResponse ToCaseDto(this Item @case, List<Item> items)
        {
            return new Dtos.CaseResponse{
                ItemId = @case.ItemId,
                ItemName = @case.ItemName,
                Items = items
            };
        }

        public static Dtos.UserResponse ToDto(this User user, List<Item> items)
        {
            return new Dtos.UserResponse {
             Id = user.UserId,
             Balance = user.Balance,
             Email = user.Email,
             InventoryItems = items,
             IsAdmin = user.IsAdmin,
             Username = user.Username,
             LoginStreak = user.LoginStreak,
             TotpEnabled = user.TotpEnabled,
             WebauthnEnabled = user.WebauthnEnabled
            };
        }
    }
}
using csgo.Models;

namespace csgo
{
    public static class Extensions
    {
        public static Dtos.SkinResponse ToDto(this Skin skin)
        {
            return new Dtos.SkinResponse(skin.SkinId, skin.SkinName, skin.SkinValue);
        }

        public static Dtos.ItemResponse ToDto(this Item item)
        {
            return new Dtos.ItemResponse(item.ItemId, item.ItemName, item.ItemDescription!, item.Rarity, item.SkinId, item.ItemValue);
        }

        public static Dtos.CaseResponse ToDto(this Case @case)
        {
            return new Dtos.CaseResponse(@case.CaseId, @case.CaseName, [.. @case.Items]);
        }

        public static Dtos.UserResponse ToDto(this User user)
        {
            return new Dtos.UserResponse(user.UserId, user.Username, user.Email, user.Balance, user.LoginStreak, user.TotpEnabled, user.WebauthnEnabled, user.IsAdmin, user.Userinventories.Select(x => x.Item).ToList()!);
        }
    }
}

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
            return new Dtos.CaseResponse(@case.CaseId, @case.CaseName, @case.Items.ToList());
        }
    }
}

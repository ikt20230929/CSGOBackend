using csgo.Models;
using static csgo.Dtos;
namespace csgo
{
    /// <summary>
    /// DTO konvertálásban segítő metódusok
    /// </summary>
    public static class Extensions
    {
        /// <summary>
        /// Tárgy modell konvertálása DTO-ra
        /// </summary>
        /// <param name="item">A Tárgy modell</param>
        /// <returns>Egy Tárgy DTO</returns>
        public static ItemResponse ToDto(this Item item)
        {
          return new ItemResponse
          {
              ItemName = item.ItemName,
              ItemDescription = item.ItemDescription,
              ItemId = item.ItemId,
              ItemRarity = item.ItemRarity,
              ItemSkinName = item.ItemSkinName ?? "Tárgy skin nevének lekérdezése sikertelen volt",
              ItemValue = item.ItemValue ?? -1,
              ItemAssetUrl = item.ItemAssetUrl,
              ItemType = item.ItemType
          };
        }
        
        /// <summary>
        /// Tárgy modell konvertálása leltár tárgy DTO-ra
        /// </summary>
        public static InventoryItemResponse ToInventoryItemDto(this Item item, int inventoryId) {
            return new InventoryItemResponse
            {
                InventoryId = inventoryId,
                ItemName = item.ItemName,
                ItemDescription = item.ItemDescription,
                ItemId = item.ItemId,
                ItemRarity = item.ItemRarity,
                ItemSkinName = item.ItemSkinName ?? "Tárgy skin nevének lekérdezése sikertelen volt",
                ItemValue = item.ItemValue ?? -1,
                ItemAssetUrl = item.ItemAssetUrl,
                ItemType = item.ItemType
            };
        }

        /// <summary>
        /// Láda modell konvertálása DTO-ra
        /// </summary>
        /// <param name="case">A Láda modell</param>
        /// <param name="items">A Ládahoz tartózó elemek listája</param>
        /// <returns>Egy Láda DTO</returns>
        public static CaseResponse ToCaseDto(this Item @case, List<ItemResponse> items)
        {
            return new CaseResponse{
                ItemId = @case.ItemId,
                ItemName = @case.ItemName,
                Items = items,
                ItemAssetUrl = @case.ItemAssetUrl,
                ItemValue = @case.ItemValue ?? -1
            };
        }

        /// <summary>
        /// Felhasználó modell konvertálása DTO-ra
        /// </summary>
        /// <param name="user">A Felhasználó modell</param>
        /// <param name="items">A felhsaználó leltárában lévő elemek listája</param>
        /// <returns>Egy Felhasználó DTO</returns>
        public static UserResponse ToDto(this User user, List<ItemResponse> items)
        {
            return new UserResponse {
             Id = user.UserId,
             Balance = user.Balance,
             Email = user.Email,
             InventoryItems = items,
             IsAdmin = user.IsAdmin,
             Username = user.Username,
             LoginStreak = user.LoginStreak,
             LastClaimDate = user.LastClaimDate,
             TotpEnabled = user.TotpEnabled,
             WebauthnEnabled = user.WebauthnEnabled
            };
        }
    }
}
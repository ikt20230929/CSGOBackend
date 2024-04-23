using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using csgo.Data;
using csgo.Models;
using Fido2NetLib;
using Fido2NetLib.Objects;
using KaimiraGames;
using OtpNet;
using static csgo.Dtos;

namespace csgo.Services
{
    /// <summary>
    /// Backend szolgáltatás
    /// </summary>
    /// <param name="caseItemRepository">A láda-tárgy kapcsolatot kezelő repository</param>
    /// <param name="giveawayRepository">A nyereményjátékokat kezelő repository</param>
    /// <param name="itemRepository">A tárgyakat kezelő repository</param>
    /// <param name="userInventoryRepository">A felhasználó leltárát kezelő repository</param>
    /// <param name="userRepository">A felhasználókat kezelő repository</param>
    /// <param name="dateTimeProvider">Dátum-idő szolgáltatás</param>
    /// <param name="totpProvider">A TOTP szolgáltatás</param>
    /// <param name="fido2">A Fido2 szolgáltatás</param>
    public class CSGOBackendService(
    ICaseItemRepository caseItemRepository,
    IGiveawayRepository giveawayRepository, 
    IItemRepository itemRepository,
    IUserInventoryRepository userInventoryRepository,
    IUserRepository userRepository,
    IDateTimeProvider dateTimeProvider,
    ITotpProvider totpProvider,
    IFido2 fido2) : ICsgoBackendService
    {
        private readonly Dictionary<ItemRarity, int> rarityWeights = new()
        {
            { ItemRarity.INDUSTRIAL_GRADE, 7992 },
            { ItemRarity.MIL_SPEC, 7992 },
            { ItemRarity.RESTRICTED, 1598 },
            { ItemRarity.CLASSIFIED, 320 },
            { ItemRarity.COVERT, 64 },
            { ItemRarity.EXTRAORDINARY, 28 }
        };

        /// <inheritdoc/>
        public async Task<ActionStatus> AddCaseAsync(CaseRecord details)
        {
            Item @case = new()
            {
                ItemName = details.Name,
                ItemType = ItemType.Case,
                ItemValue = details.Value,
                ItemAssetUrl = details.AssetUrl ?? null
            };

            await itemRepository.AddAsync(@case);

            return new ActionStatus { Status = "OK", Message = @case.ToCaseDto([]) };
        }

        /// <inheritdoc/>
        public async Task<ActionStatus> AddCaseItemAsync(int caseId, int itemId)
        {
            var @case = await itemRepository.GetCaseByIdAsync(caseId);
            var item = await itemRepository.GetItemByIdAsync(itemId);

            if (@case == null) return new ActionStatus { Status = "ERR", Message = "A megadott láda nem található." };
            if (item == null) return new ActionStatus { Status = "ERR", Message = "A megadott tárgy nem található." };

            await caseItemRepository.AddAsync(new CaseItem { CaseId = caseId, ItemId = itemId });

            var caseItems = await caseItemRepository.GetCaseItemsAsync(caseId);

            return new ActionStatus { Status = "OK", Message = @case.ToCaseDto(caseItems.Select(x => x.Item.ToDto()).ToList()) };
        }

        /// <inheritdoc/>
        public async Task<ActionStatus> AddGiveawayAsync(GiveawayRecord details)
        {
            var item = await itemRepository.GetItemByIdAsync(details.ItemId);
            if (item == null) return new ActionStatus { Status = "ERR", Message = "A megadott tárgy nem található." };

            var giveaway = new Giveaway
            {
                ItemId = item.ItemId,
                GiveawayDate = details.Date.ToLocalTime(),
                GiveawayDescription = details.Description,
                GiveawayName = details.Name,
            };

            await giveawayRepository.AddAsync(giveaway);

            return new ActionStatus
            {
                Status = "OK",
                Message = new CurrentGiveawayResponse
                {
                    GiveawayDate = giveaway.GiveawayDate,
                    GiveawayDescription = giveaway.GiveawayDescription,
                    GiveawayId = giveaway.GiveawayId,
                    GiveawayItem = giveaway.Item?.ItemName ?? "Név lekérése sikertelen volt.",
                    GiveawayName = giveaway.GiveawayName
                }
            };
        }

        /// <inheritdoc/>
        public async Task<ActionStatus> AddInventoryItemAsync(int userId, int itemId)
        {
            var target = await userRepository.GetByIdAsync(userId);
            var item = await itemRepository.GetItemByIdAsync(itemId);

            if (target == null) return new ActionStatus { Status = "ERR", Message = "A megadott felhasználó nem található." };
            if (item == null) return new ActionStatus { Status = "ERR", Message = "A megadott tárgy nem található." };

            await userInventoryRepository.AddAsync(new Userinventory { ItemId = itemId, UserId = userId });

            var userInventoryItems = await userInventoryRepository.GetUserInventoryAsync(userId);
            List<InventoryItemResponse> items = userInventoryItems.Select(x => x.Item.ToInventoryItemDto(x.InventoryId)).ToList();

            return new ActionStatus { Status = "OK", Message = items };

        }

        /// <inheritdoc/>
        public async Task<ActionStatus> AddItemAsync(ItemRecord details)
        {
            Item item = new()
            {
                ItemType = ItemType.Item,
                ItemName = details.Name,
                ItemDescription = details.Description,
                ItemRarity = details.Rarity,
                ItemSkinName = details.SkinName,
                ItemValue = details.Value,
                ItemAssetUrl = details.AssetUrl ?? null
            };

            await itemRepository.AddAsync(item);

            return new ActionStatus { Status = "OK", Message = item.ToDto() };
        }

        /// <inheritdoc/>
        public async Task<ActionStatus> CheckTotpTokenAsync(User user, EnableTOTPRequest request)
        {
            if (user.TotpEnabled) return new ActionStatus { Status = "ERR", Message = "A kétlépcsős azonosítás már engedélyezve van." };

            bool verify = totpProvider.VerifyTotp(Base32Encoding.ToBytes(user.TotpSecret), request.Code);

            if (verify)
            {
                user.TotpEnabled = true;
                await userRepository.UpdateAsync(user);
                return new ActionStatus { Status = "OK", Message = "A kétlépcsős azonosítás sikeresen engedélyezve lett." };
            }
            else
            {
                return new ActionStatus { Status = "ERR", Message = "Érvénytelen kód." };
            }
        }

        /// <inheritdoc/>
        public async Task<ActionStatus> ClaimDailyRewardAsync(User user)
        {
            if (user.LastClaimDate.Date == dateTimeProvider.Now.Date) return new ActionStatus { Status = "ERR", Message = "A napi jutalom már igényelve lett." };

            // Ha az utolsó kérés dátuma nem az aktuális hónapban van, akkor a streaket nullázni kell.
            if (user.LastClaimDate.Month != dateTimeProvider.Now.Month) user.LoginStreak = 1;

            int reward = 5;

            if (user.LastClaimDate.Date.AddDays(1) == dateTimeProvider.Now.Date)
            {
                user.LoginStreak++;
                if (user.LoginStreak == 3) reward *= 2;
                if (user.LoginStreak == 7) reward *= 3;
                if (user.LoginStreak == 14) reward *= 4;
                if (user.LoginStreak == 30) reward *= 5;
            }
            else
            {
                user.LoginStreak = 1;
            }

            user.LastClaimDate = dateTimeProvider.Now;
            user.Balance += reward;

            await userRepository.UpdateAsync(user);

            return new ActionStatus { Status = "OK", Message = reward };
        }

        /// <inheritdoc/>
        public async Task<ActionStatus> DeleteCaseAsync(int caseId)
        {
            var @case = await itemRepository.GetCaseByIdAsync(caseId);

            if (@case == null) return new ActionStatus { Status = "ERR", Message = "A megadott láda nem található." };

            var inventoryItems = await userInventoryRepository.GetInventoryItemsByItemIdAsync(caseId);

            foreach (var item in inventoryItems)
            {
                await userInventoryRepository.DeleteAsync(item);
            }

            await itemRepository.DeleteAsync(@case);

            return new ActionStatus { Status = "OK", Message = "A láda sikeresen törölve lett." };
        }

        /// <inheritdoc/>
        public async Task<ActionStatus> DeleteCaseItemAsync(int caseId, int itemId)
        {
            var @case = await itemRepository.GetCaseByIdAsync(caseId);
            var item = await itemRepository.GetItemByIdAsync(itemId);

            if (@case == null) return new ActionStatus { Status = "ERR", Message = "A megadott láda nem található." };
            if (item == null) return new ActionStatus { Status = "ERR", Message = "A megadott tárgy nem található." };

            var caseItem = await caseItemRepository.GetCaseItemByIdAsync(caseId, itemId);
            if (caseItem == null) return new ActionStatus { Status = "ERR", Message = "A megadott tárgy nem található a ládában." };

            await caseItemRepository.DeleteAsync(caseItem);

            var caseItems = await caseItemRepository.GetCaseItemsAsync(caseId);

            return new ActionStatus { Status = "OK", Message = @case.ToCaseDto(caseItems.Select(x => x.Item.ToDto()).ToList()) };
        }

        /// <inheritdoc/>
        public async Task<ActionStatus> DeleteGiveawayAsync(int giveawayId)
        {
            var giveaway = await giveawayRepository.GetByIdAsync(giveawayId);

            if (giveaway == null) return new ActionStatus { Status = "ERR", Message = "A megadott nyereményjáték nem található." };

            var participants = await giveawayRepository.GetParticipantsAsync(giveaway);

            foreach (var participant in participants)
            {
                participant.Giveaways.Remove(giveaway);
                await userRepository.UpdateAsync(participant);
            }

            await giveawayRepository.DeleteAsync(giveaway);

            return new ActionStatus { Status = "OK", Message = "A nyereményjáték sikeresen törölve lett." };
        }

        /// <inheritdoc/>
        public async Task<ActionStatus> DeleteInventoryItemAsync(int userId, int itemId)
        {
            var target = await userRepository.GetByIdAsync(userId);
            var item = await itemRepository.GetItemByIdAsync(itemId);
            if (target == null) return new ActionStatus { Status = "ERR", Message = "A megadott felhasználó nem található." };
            if (item == null) return new ActionStatus { Status = "ERR", Message = "A megadott tárgy nem található." };

            var userInventoryItems = await userInventoryRepository.GetUserInventoryAsync(userId);
            var userInventory = userInventoryItems.FirstOrDefault(x => x.ItemId == itemId);
            if (userInventory == null) return new ActionStatus { Status = "ERR", Message = "A megadott tárgy nem található a felhasználó leltárában." };

            await userInventoryRepository.DeleteAsync(userInventory);

            List<InventoryItemResponse> items = userInventoryItems.Where(x => x.InventoryId != userInventory.InventoryId).Select(x => x.Item.ToInventoryItemDto(x.InventoryId)).ToList();

            return new ActionStatus { Status = "OK", Message = items };
        }

        /// <inheritdoc/>
        public async Task<ActionStatus> DeleteItemAsync(int itemId)
        {
            var item = await itemRepository.GetItemByIdAsync(itemId);

            if (item == null) return new ActionStatus { Status = "ERR", Message = "A megadott tárgy nem található." };

            var inventories = await userInventoryRepository.GetInventoryItemsByItemIdAsync(itemId);

            foreach (var inventoryItem in inventories)
            {
                await userInventoryRepository.DeleteAsync(inventoryItem);
            }

            await itemRepository.DeleteAsync(item);

            return new ActionStatus { Status = "OK", Message = "A tárgy sikeresen törölve lett." };
        }

        /// <inheritdoc/>
        public async Task<ActionStatus> DepositAsync(User user, double amount)
        {
            if (amount <= 0) return new ActionStatus { Status = "ERR", Message = "Az összeg nem lehet negatív." };

            user.Balance += amount;
            await userRepository.UpdateAsync(user);

            return new ActionStatus { Status = "OK", Message = $"Sikeresen befizetve: ${amount}." };
        }

        /// <inheritdoc/>
        public async Task<ActionStatus> DisableTotpAsync(User user, DisableTOTPRequest request)
        {
            if (!user.TotpEnabled) return new ActionStatus { Status = "ERR", Message = "A kétlépcsős azonosítás nincs engedélyezve." };

            if (!BCrypt.Net.BCrypt.Verify(request.Password, user.PasswordHash)) return new ActionStatus { Status = "ERR", Message = "Érvénytelen jelszó." };

            bool verify = totpProvider.VerifyTotp(Base32Encoding.ToBytes(user.TotpSecret), request.Code);

            if (verify)
            {
                user.TotpEnabled = false;
                await userRepository.UpdateAsync(user);
                return new ActionStatus { Status = "OK", Message = "A kétlépcsős azonosítás sikeresen ki lett kapcsolva." };
            }
            else
            {
                return new ActionStatus { Status = "ERR", Message = "Érvénytelen kód." };
            }
        }

        /// <inheritdoc/>
        public async Task<ActionStatus> GenerateTotpTokenAsync(User user)
        {
            if (user.TotpEnabled) return new ActionStatus { Status = "ERR", Message = "A kétlépcsős azonosítás már engedélyezve van." };

            user.TotpSecret = Base32Encoding.ToString(KeyGeneration.GenerateRandomKey(20));
            await userRepository.UpdateAsync(user);

            return new ActionStatus { Status = "OK", Message = user.TotpSecret };
        }

        /// <inheritdoc/>
        public async Task<ActionStatus> GetCasesAsync()
        {
            var items = await itemRepository.GetAllCasesAsync();

            var caseDtos = new List<CaseResponse>();

            foreach (var item in items)
            {
                var caseItems = await caseItemRepository.GetCaseItemsAsync(item.ItemId);
                var caseDto = item.ToCaseDto(caseItems.Select(x => x.Item.ToDto()).ToList());
                caseDtos.Add(caseDto);
            }

            return new ActionStatus { Status = "OK", Message = caseDtos };
        }

        /// <inheritdoc/>
        public async Task<ActionStatus> GetGiveawaysAsync(User user)
        {
            var giveaways = await giveawayRepository.GetCurrentGiveawaysAsync();

            var mapped = giveaways.Select(giveaway => new CurrentGiveawayResponse
            {
                GiveawayId = giveaway.GiveawayId,
                GiveawayName = giveaway.GiveawayName,
                GiveawayDescription = giveaway.GiveawayDescription ?? "Leírás lekérése sikertelen volt.",
                GiveawayDate = giveaway.GiveawayDate,
                GiveawayItem = giveaway.Item?.ItemName ?? "Név lekérése sikertelen volt.",
                GiveawayItemAssetUrl = giveaway.Item?.ItemAssetUrl ?? "error.png",
                GiveawayItemSkinName = giveaway.Item?.ItemSkinName ?? "Skin név lekérése sikertelen volt.",
                GiveawayJoined = giveaway.Users.Contains(user)
            }).ToList();

            return new ActionStatus { Status = "OK", Message = mapped };
        }

        /// <inheritdoc/>
        public async Task<ActionStatus> GetInventoryAsync(User user)
        {
            List<InventoryItemResponse> items = (await userInventoryRepository.GetUserInventoryAsync(user.UserId)).Select(x => x.Item.ToInventoryItemDto(x.InventoryId)).ToList();

            return new ActionStatus { Status = "OK", Message = items };
        }

        /// <inheritdoc/>
        public async Task<ActionStatus> GetPastGiveawaysAsync()
        {
            var giveaways = await giveawayRepository.GetPastGiveawaysAsync();

            var mapped = giveaways.Select(giveaway => new PastGiveawayResponse
            {
                GiveawayDescription = giveaway.GiveawayDescription,
                GiveawayItem = giveaway.Item?.ItemName,
                GiveawayItemAssetUrl = giveaway.Item?.ItemAssetUrl,
                GiveawayItemSkinName = giveaway.Item?.ItemSkinName,
                GiveawayName = giveaway.GiveawayName,
                GiveawayId = giveaway.GiveawayId,
                GiveawayDate = giveaway.GiveawayDate,
                WinnerName = giveaway.WinnerUser?.Username
            }).ToList();

            return new ActionStatus { Status = "OK", Message = mapped };
        }

        /// <inheritdoc/>
        public async Task<ActionStatus> GetProfileAsync(User user)
        {
            return await Task.Run(() => new ActionStatus { Status = "OK", Message = user.ToDto(null!) });
        }

        /// <inheritdoc/>
        public async Task<ActionStatus> GetUpgradeItemsAsync(User user, ItemUpgradeListRequest request)
        {
            var userItems = await userInventoryRepository.GetUserInventoryAsync(user.UserId);

            foreach (var item in request.Items)
            {
                if (!userItems.Any(x => x.InventoryId == item)) return new ActionStatus { Status = "ERR", Message = "A megadott tárgy nem található a leltárban." };
            }

            List<InventoryItemResponse> itemData = userItems.Where(x => request.Items.Contains(x.InventoryId)).Select(x => x.Item.ToInventoryItemDto(x.InventoryId)).ToList();

            var totalValue = itemData.Sum(x => x.ItemValue);

            var upgradeItems = await itemRepository.GetUpgradeItemsAsync(totalValue);

            if (upgradeItems.Count == 0) return new ActionStatus { Status = "ERR", Message = "A tárgy nem fejleszthető tovább." };

            return new ActionStatus { Status = "OK", Message = upgradeItems.Where(y => GetItemUpgradeSuccessChance(totalValue, y) > 0).Select(x => new { Item = x.ToDto(), Chance = GetItemUpgradeSuccessChance(totalValue, x), Multiplier = Math.Round((decimal)x.ItemValue! / totalValue, 2) }) };
        }

        /// <inheritdoc/>
        public async Task<ActionStatus> GetUserAsync(string username)
        {
            User? user = await userRepository.GetByUsernameAsync(username);

            if (user == null) return new ActionStatus { Status = "ERR", Message = "A felhasználó nem található." };

            return new ActionStatus { Status = "OK", Message = user };
        }

        /// <inheritdoc/>
        public async Task<ActionStatus> GetUsersAsync()
        {
            var users = await userRepository.GetAllAsync();

            var userDtos = new List<UserResponse>();

            foreach (var u in users)
            {
                var items = await userInventoryRepository.GetUserInventoryAsync(u.UserId);
                userDtos.Add(u.ToDto(items.Select(x => x.Item.ToDto()).ToList()));
            }

            return new ActionStatus { Status = "OK", Message = userDtos };
        }

        /// <inheritdoc/>
        public async Task<ActionStatus> JoinGiveawayAsync(User user, int id)
        {
            var giveaway = await giveawayRepository.GetByIdAsync(id);

            if (giveaway == null) return new ActionStatus { Status = "ERR", Message = "A megadott nyereményjáték nem található." };
            if (giveaway.GiveawayDate < dateTimeProvider.Now) return new ActionStatus { Status = "ERR", Message = "A nyereményjáték már lezárult." };
            if (giveaway.Users.Contains(user)) return new ActionStatus { Status = "ERR", Message = "Már csatlakoztál a nyereményjátékhoz." };

            giveaway.Users.Add(user);
            await giveawayRepository.UpdateAsync(giveaway);

            return new ActionStatus { Status = "OK", Message = "Sikeresen csatlakoztál a nyereményjátékhoz." };
        }

        /// <inheritdoc/>
        public async Task<ActionStatus> LoginUserAsync(LoginRequest login, string? jsonOptions = null)
        {
            var request = await GetUserAsync(login.Username);
            if (request.Status == "ERR") return request;

            User storedUser = request.Message;

            string? twoFactorScenario = null;

            if (storedUser is { TotpEnabled: true, WebauthnEnabled: true })
            {
                twoFactorScenario = "PickTwoFactor";
            }
            else if (storedUser.TotpEnabled)
            {
                twoFactorScenario = "EnterTotp";
            }
            else if (storedUser.WebauthnEnabled)
            {
                twoFactorScenario = "EnterWebAuthn";
            }

            if (twoFactorScenario == null) return CheckPassword(login.Password, storedUser);
            if (login.Mfa == null) return new ActionStatus { Status = "UI", Message = twoFactorScenario };

            switch (login.Mfa.MfaType)
            {
                case MfaType.Totp:
                    {
                        if (!storedUser.TotpEnabled) return new ActionStatus { Status = "ERR", Message = "Helytelen hitelesítési mód." };
                        if (login.Mfa.TotpToken == null) return new ActionStatus { Status = "ERR", Message = "Helytelen kód." };

                        bool verify = totpProvider.VerifyTotp(Base32Encoding.ToBytes(storedUser.TotpSecret), login.Mfa.TotpToken);

                        return verify ? CheckPassword(login.Password, storedUser) : new ActionStatus { Status = "ERR", Message = "Helytelen kód." };
                    }
                case MfaType.WebAuthnOptions:
                    {
                        if (!storedUser.WebauthnEnabled) return new ActionStatus { Status = "ERR", Message = "Helytelen hitelesítési mód." };
                        if (storedUser.WebauthnCredentialId == null || storedUser.WebauthnPublicKey == null) return new ActionStatus { Status = "ERR", Message = "Helytelen válasz." };

                        var credential = JsonSerializer.Deserialize<StoredCredential>(storedUser.WebauthnPublicKey);

                        if (credential == null) return new ActionStatus { Status = "ERR", Message = "Helytelen válasz." };

                        var options = fido2.GetAssertionOptions([credential.Descriptor], UserVerificationRequirement.Discouraged);

                        return new ActionStatus { Status = "UI", Message = options.ToJson() };
                    }
                case MfaType.WebAuthnAssertion:
                    {
                        if (!storedUser.WebauthnEnabled) return new ActionStatus { Status = "ERR", Message = "Helytelen hitelesítési mód." };
                        if (storedUser.WebauthnCredentialId == null || storedUser.WebauthnPublicKey == null || login.Mfa.WebAuthnAssertationResponse == null) return new ActionStatus { Status = "ERR", Message = "Helytelen válasz." };

                        var options = AssertionOptions.FromJson(jsonOptions);
                        var credential = JsonSerializer.Deserialize<StoredCredential>(storedUser.WebauthnPublicKey);

                        if (credential == null) return new ActionStatus { Status = "ERR", Message = "Helytelen válasz." };

                        var result = await fido2.MakeAssertionAsync(
                            login.Mfa.WebAuthnAssertationResponse,
                            options,
                            credential.PublicKey,
                            credential.DevicePublicKeys,
                            credential.SignCount,
                            IsUserHandleOwnerOfCredentialId);

                        if (result.Status != "ok") return new ActionStatus { Status = "ERR", Message = "Helytelen válasz." };

                        var storedCredential = new StoredCredential
                        {
                            DevicePublicKeys = credential.DevicePublicKeys,
                            Id = result.CredentialId,
                            Descriptor = new PublicKeyCredentialDescriptor(result.CredentialId),
                            PublicKey = credential.PublicKey,
                            UserHandle = credential.UserHandle,
                            SignCount = result.SignCount,
                            RegDate = credential.RegDate,
                            AaGuid = credential.AaGuid
                        };

                        storedUser.WebauthnPublicKey = JsonSerializer.Serialize(storedCredential);
                        await userRepository.UpdateAsync(storedUser);

                        return CheckPassword(login.Password, storedUser);
                    }
                default:
                    {
                        return new ActionStatus { Status = "ERR", Message = "Helytelen felhasználónév vagy jelszó." };
                    }
            }
        }

        private ActionStatus CheckPassword(string password, User storedUser)
        {
            if (!BCrypt.Net.BCrypt.Verify(password, storedUser.PasswordHash))
            {
                return new ActionStatus { Status = "ERR", Message = "Helytelen felhasználónév vagy jelszó." };
            }

            var (accessToken, refreshToken) = GenerateTokens(storedUser);
            return new ActionStatus { Status = "OK", Message = (accessToken, refreshToken) };
        }

        /// <inheritdoc/>
        public (string accessToken, string refreshToken) GenerateTokens(User user)
        {
            var claims = new List<Claim>
            {
                new("name", user.Username),
                new("email", user.Email)
            };

            // Access token létrehozása
            var accessToken = new JwtSecurityToken(
                issuer: Globals.Config.BackUrl,
                audience: Globals.Config.BackUrl,
                claims: claims,
                expires: dateTimeProvider.Now.AddMinutes(30),
                signingCredentials: Signing.AccessTokenCreds);
            var accessTokenString = new JwtSecurityTokenHandler().WriteToken(accessToken);

            // Refresh token létrehozása
            var refreshToken = new JwtSecurityToken(
                issuer: Globals.Config.BackUrl,
                audience: Globals.Config.BackUrl,
                claims: claims,
                expires: dateTimeProvider.Now.AddDays(7),
                signingCredentials: Signing.RefreshTokenCreds);
            var refreshTokenString = new JwtSecurityTokenHandler().WriteToken(refreshToken);

            return (accessTokenString, refreshTokenString);
        }

        private async Task<bool> IsUserHandleOwnerOfCredentialId(IsUserHandleOwnerOfCredentialIdParams arg, CancellationToken cancellationToken)
        {
            var user = await userRepository.GetByIdAsync(Convert.ToInt32(Encoding.UTF8.GetString(arg.UserHandle)));

            if (user == null || user.WebauthnPublicKey == null) return false;

            var credential = JsonSerializer.Deserialize<StoredCredential>(user.WebauthnPublicKey);

            return credential?.UserHandle.SequenceEqual(arg.UserHandle) ?? false;
        }

        /// <inheritdoc/>
        public async Task<ActionStatus> OpenCaseAsync(User user, int caseId)
        {
            var @case = await itemRepository.GetCaseByIdAsync(caseId);
            if (@case == null) return new ActionStatus { Status = "ERR", Message = "A megadott láda nem található." };

            if ((decimal)user.Balance < @case.ItemValue) return new ActionStatus { Status = "ERR", Message = "Nincs elég egyenleged a láda megnyitásához." };

            var ctxCaseItems = await caseItemRepository.GetCaseItemsAsync(caseId);

            var weights = new Dictionary<Item, double>();
            foreach (var item in ctxCaseItems)
            {
                double rarityWeight = rarityWeights[item.Item.ItemRarity];
                double valueRatio = (double)item.Item.ItemValue! / (double)@case.ItemValue!;
                double valueWeight = 1 / (1 + valueRatio);
                var totalWeight = rarityWeight * valueWeight;
                weights[item.Item] = totalWeight;
            }

            var itemList = ctxCaseItems.Select(item => new WeightedListItem<Item>(item.Item, (int)weights[item.Item])).ToList();

            var caseItems = new WeightedList<Item>(itemList);
            var resultItem = caseItems.Next();

            await userInventoryRepository.AddAsync(new Userinventory { ItemId = resultItem.ItemId, UserId = user.UserId });

            user.Balance -= Convert.ToDouble(@case.ItemValue);

            await userRepository.UpdateAsync(user);

            return new ActionStatus { Status = "OK", Message = resultItem.ToDto() };
        }

        /// <inheritdoc/>
        public async Task<ActionStatus> RegisterAsync(RegisterRequest register)
        {
            User newUser = new()
            {
                Email = register.Email,
                Username = register.Username
            };

            if (await userRepository.UsernameExistsAsync(register.Username))
            {
                return new ActionStatus { Status = "ERR", Message = "A megadott felhasználónév már foglalt." };
            }

            if (await userRepository.EmailExistsAsync(register.Email))
            {
                return new ActionStatus { Status = "ERR", Message = "Az megadott e-mail már használatban van." };
            }

            string hashedPassword = BCrypt.Net.BCrypt.HashPassword(register.Password);
            newUser.PasswordHash = hashedPassword;
            await userRepository.AddAsync(newUser);

            return new ActionStatus { Status = "OK", Message = "Sikeres regisztráció!" };
        }

        /// <inheritdoc/>
        public async Task<ActionStatus> SellItemAsync(User user, int inventoryId)
        {
            var inventoryItems = await userInventoryRepository.GetUserInventoryAsync(user.UserId);
            if (!inventoryItems.Any(x => x.InventoryId == inventoryId)) return new ActionStatus { Status = "ERR", Message = "A megadott tárgy nem található a leltárban." };

            var inventoryItem = inventoryItems.First(x => x.InventoryId == inventoryId);

            user.Balance += Convert.ToDouble(inventoryItem.Item.ItemValue);
            await userInventoryRepository.DeleteAsync(inventoryItem);

            return new ActionStatus { Status = "OK", Message = "A tárgy sikeresen eladva." };
        }

        /// <inheritdoc/>
        public async Task<ActionStatus> UpdateCaseAsync(int caseId, CaseRecord details)
        {
            var @case = await itemRepository.GetCaseByIdAsync(caseId);
            if (@case == null) return new ActionStatus { Status = "ERR", Message = "A megadott láda nem található." };

            @case.ItemName = details.Name;
            @case.ItemValue = details.Value;
            if (details.AssetUrl != null) @case.ItemAssetUrl = details.AssetUrl;

            await itemRepository.UpdateAsync(@case);

            var caseItems = await caseItemRepository.GetCaseItemsAsync(caseId);

            return new ActionStatus { Status = "OK", Message = @case.ToCaseDto(caseItems.Select(x => x.Item.ToDto()).ToList()) };
        }

        /// <inheritdoc/>
        public async Task<ActionStatus> UpdateGiveawayAsync(int giveawayId, GiveawayRecord details)
        {
            var giveaway = await giveawayRepository.GetByIdAsync(giveawayId);
            if (giveaway == null) return new ActionStatus { Status = "ERR", Message = "A megadott nyereményjáték nem található." };
            if (giveaway.GiveawayDate < dateTimeProvider.Now) return new ActionStatus { Status = "ERR", Message = "Lefutott nyereményjátékot nem lehet módosítani." };
            if (details.Date < dateTimeProvider.Now) return new ActionStatus { Status = "ERR", Message = "A nyereményjáték dátuma nem lehet a múltban." };

            var item = await itemRepository.GetItemByIdAsync(details.ItemId);
            if (item == null) return new ActionStatus { Status = "ERR", Message = "A megadott tárgy nem található." };

            giveaway.GiveawayDate = details.Date.ToLocalTime();
            giveaway.GiveawayDescription = details.Description;
            giveaway.GiveawayName = details.Name;
            giveaway.ItemId = item.ItemId;

            await giveawayRepository.UpdateAsync(giveaway);

            return new ActionStatus
            {
                Status = "OK",
                Message = new CurrentGiveawayResponse
                {
                    GiveawayDate = giveaway.GiveawayDate,
                    GiveawayDescription = giveaway.GiveawayDescription,
                    GiveawayId = giveaway.GiveawayId,
                    GiveawayItem = giveaway.Item?.ItemName ?? "Név lekérése sikertelen volt.",
                    GiveawayName = giveaway.GiveawayName
                }
            };
        }

        /// <inheritdoc/>
        public async Task<ActionStatus> UpdateItemAsync(int itemId, ItemRecord details)
        {
            var item = await itemRepository.GetItemByIdAsync(itemId);
            if (item == null) return new ActionStatus { Status = "ERR", Message = "A megadott tárgy nem található." };

            item.ItemName = details.Name;
            item.ItemDescription = details.Description;
            item.ItemRarity = details.Rarity;
            item.ItemSkinName = details.SkinName;
            item.ItemValue = details.Value;
            if (details.AssetUrl != null) item.ItemAssetUrl = details.AssetUrl;

            await itemRepository.UpdateAsync(item);

            return new ActionStatus { Status = "OK", Message = item.ToDto() };
        }

        /// <inheritdoc/>
        public async Task<ActionStatus> UpdateUserAsync(int userId, UserEditRecord details)
        {
            var target = await userRepository.GetByIdAsync(userId);
            if (target == null) return new ActionStatus { Status = "ERR", Message = "A megadott felhasználó nem található." };

            if (await userRepository.UsernameExistsAsync(details.Username, userId)) return new ActionStatus { Status = "ERR", Message = "A megadott felhasználónév már foglalt." };
            if (await userRepository.EmailExistsAsync(details.Email, userId)) return new ActionStatus { Status = "ERR", Message = "Az megadott e-mail már használatban van." };

            target.Username = details.Username;
            target.Email = details.Email;
            target.Balance = details.Balance;

            await userRepository.UpdateAsync(target);

            var items = await userInventoryRepository.GetUserInventoryAsync(userId);
            return new ActionStatus { Status = "OK", Message = target.ToDto(items.Select(x => x.Item.ToDto()).ToList()) };
        }

        /// <inheritdoc/>
        public async Task<ActionStatus> UpgradeItemAsync(User user, ItemUpgradeRequest request)
        {
            var userInventory = await userInventoryRepository.GetUserInventoryAsync(user.UserId);

            foreach (var item in request.Items)
            {
                if (!userInventory.Any(x => x.InventoryId == item)) return new ActionStatus { Status = "ERR", Message = "A megadott tárgy nem található a leltárban." };
            }

            List<InventoryItemResponse> itemData = request.Items.Select(x => userInventory.First(y => y.InventoryId == x).Item.ToInventoryItemDto(x)).ToList();

            var nextItem = await itemRepository.GetItemByIdAsync(request.Target);
            if (nextItem == null) return new ActionStatus { Status = "ERR", Message = "A megadott tárgy nem található." };

            var totalValue = itemData.Sum(x => x.ItemValue);

            if (GetRandomDouble() < GetItemUpgradeSuccessChance(totalValue, nextItem))
            {
                foreach (var item in itemData)
                {
                    var inventoryItem = userInventory.First(x => x.InventoryId == item.InventoryId);
                    await userInventoryRepository.DeleteAsync(inventoryItem);
                }

                await userInventoryRepository.AddAsync(new Userinventory { ItemId = nextItem.ItemId, UserId = user.UserId });

                return new ActionStatus
                {
                    Status = "OK",
                    Message = new ItemUpgradeResponse
                    {
                        Success = true,
                        Item = nextItem.ToDto()
                    }
                };
            }
            else
            {
                foreach (var item in itemData)
                {
                    var inventoryItem = userInventory.First(x => x.InventoryId == item.InventoryId);
                    await userInventoryRepository.DeleteAsync(inventoryItem);
                }

                return new ActionStatus
                {
                    Status = "OK",
                    Message = new ItemUpgradeResponse
                    {
                        Success = false,
                        Item = null
                    }
                };
            }
        }

        /// <inheritdoc/>
        public async Task<ActionStatus> UploadImageAsync(IFormFile image)
        {
            try
            {
                if (image.Length == 0)
                {
                    return new ActionStatus { Status = "ERR", Message = "Nincs megadva kép." };
                }

                var allowedExtensions = new[] { ".jpg", ".jpeg", ".jpeg2000", ".png", ".gif" };
                var extension = Path.GetExtension(image.FileName).ToLower();

                if (!allowedExtensions.Contains(extension))
                {
                    return new ActionStatus { Status = "ERR", Message = "Nem megfelelő képformátum." };
                }

                using (var reader = new BinaryReader(image.OpenReadStream()))
                {
                    var signatures = _fileSignatures.Values.SelectMany(x => x).ToList();
                    var headerBytes = reader.ReadBytes(_fileSignatures.Max(m => m.Value.Max(n => n.Length)));
                    bool result = signatures.Any(signature => headerBytes.Take(signature.Length).SequenceEqual(signature));

                    if (!result)
                    {
                        return new ActionStatus { Status = "ERR", Message = "Nem megfelelő képformátum." };
                    }
                }

                var fileName = Path.GetRandomFileName() + Path.GetExtension(image.FileName);
                var filePath = Path.Combine("uploads", fileName);

                await using (var stream = new FileStream(filePath, FileMode.Create))
                {
                    await image.CopyToAsync(stream);
                }

                var imageUrl = $"/api/images/{fileName}";

                return new ActionStatus { Status = "OK", Message = imageUrl };
            }
            catch (Exception ex)
            {
                return new ActionStatus { Status = "ERR", Message = ex.Message };
            }
        }

        /// <inheritdoc/>
        public async Task<ActionStatus> WebAuthnAttestationAsync(User user, WebauthnAttestationRequest details, string? jsonOptions = null)
        {
            if (user.WebauthnEnabled) return new ActionStatus { Status = "ERR", Message = "A WebAuthn már engedélyezve van." };

            switch (details.Mode)
            {
                case WebAuthnAttestationMode.OPTIONS:
                    {
                        var fidoUser = new Fido2User
                        {
                            DisplayName = user.Username,
                            Name = user.Username,
                            Id = Encoding.UTF8.GetBytes(user.UserId.ToString())
                        };

                        var options = fido2.RequestNewCredential(fidoUser, [], new AuthenticatorSelection
                        {
                            ResidentKey = ResidentKeyRequirement.Preferred,
                            UserVerification = UserVerificationRequirement.Preferred
                        }, AttestationConveyancePreference.None, new AuthenticationExtensionsClientInputs
                        {
                            CredProps = true
                        });

                        return new ActionStatus { Status = "OK", Message = options.ToJson() };
                    }

                case WebAuthnAttestationMode.ATTESTATION:
                    {
                        try
                        {
                            if (details.Data == null) return new ActionStatus { Status = "ERR", Message = "Érvénytelen válasz." };
                            if (jsonOptions == null) return new ActionStatus { Status = "ERR", Message = "Érvénytelen művelet." };
                            var options = CredentialCreateOptions.FromJson(jsonOptions);

                            var fidoCredentials = await fido2.MakeNewCredentialAsync(details.Data, options, IsCredentialIdUniqueToUser, CancellationToken.None);

                            if (fidoCredentials.Result == null || fidoCredentials.Status != "ok") return new ActionStatus { Status = "ERR", Message = "Érvénytelen válasz." };

                            var storedCredential = new StoredCredential
                            {
                                Id = fidoCredentials.Result.Id,
                                Descriptor = new PublicKeyCredentialDescriptor(fidoCredentials.Result.Id),
                                PublicKey = fidoCredentials.Result.PublicKey,
                                UserHandle = fidoCredentials.Result.User.Id,
                                SignCount = fidoCredentials.Result.SignCount,
                                RegDate = dateTimeProvider.Now,
                                AaGuid = fidoCredentials.Result.AaGuid
                            };

                            user.WebauthnCredentialId = Convert.ToBase64String(fidoCredentials.Result.Id);
                            user.WebauthnPublicKey = JsonSerializer.Serialize(storedCredential);
                            user.WebauthnEnabled = true;

                            await userRepository.UpdateAsync(user);

                            return new ActionStatus { Status = "OK", Message = "A WebAuthn sikeresen engedélyezve lett." };
                        }
                        catch (Exception e)
                        {
                            return new ActionStatus { Status = "ERR", Message = e.Message };
                        }
                    }
                    default:
                    {
                        return new ActionStatus { Status = "ERR", Message = "Érvénytelen művelet." };
                    }
            }
        }

        /// <inheritdoc/>
        public async Task<ActionStatus> DisableWebauthnAsync(User user, WebauthnDisableRequest request, string? jsonOptions = null) {
            if (!user.WebauthnEnabled) return new ActionStatus { Status = "ERR", Message = "A WebAuthn nincs engedélyezve." };

            switch (request.Mode)
            {
                case WebAuthnAttestationMode.OPTIONS: {
                    var credential = JsonSerializer.Deserialize<StoredCredential>(user.WebauthnPublicKey!);
                    var options = fido2.GetAssertionOptions([credential!.Descriptor], UserVerificationRequirement.Discouraged);
                    return new ActionStatus { Status = "OK", Message = options.ToJson() };
                }

                case WebAuthnAttestationMode.ATTESTATION: {
                        if (request.Data == null) return new ActionStatus { Status = "ERR", Message = "Érvénytelen művelet." };

                        var options = AssertionOptions.FromJson(jsonOptions);
                        var credential = JsonSerializer.Deserialize<StoredCredential>(user.WebauthnPublicKey!);

                        if (credential == null) return new ActionStatus { Status = "ERR", Message = "Érvénytelen művelet." };

                        var result = await fido2.MakeAssertionAsync(
                            request.Data,
                            options,
                            credential.PublicKey,
                            credential.DevicePublicKeys,
                            credential.SignCount,
                            IsUserHandleOwnerOfCredentialId);

                        if (result.Status != "ok") return new ActionStatus { Status = "ERR", Message = "A hitelesítés nem sikerült." };

                        user.WebauthnEnabled = false;
                        user.WebauthnCredentialId = null;
                        user.WebauthnPublicKey = null;

                        await userRepository.UpdateAsync(user);

                        return new ActionStatus { Status = "OK", Message = "A WebAuthn sikeresen kikapcsolva lett." };
                }

                default: {
                    return new ActionStatus { Status = "ERR", Message = "Érvénytelen művelet." };
                }
            }
        }

        /// <inheritdoc/>
        public async Task<ActionStatus> WithdrawItemsAsync(User user, ItemWithdrawRequest request)
        {
            var userItems = await userInventoryRepository.GetUserInventoryAsync(user.UserId);

            foreach (var item in request.Items)
            {
                if (!userItems.Any(x => x.InventoryId == item)) return new ActionStatus { Status = "ERR", Message = "A megadott tárgy nem található a leltárban." };
            }

            // Valójában csak kitöröljük a tárgyakat a leltárból, mert nincs külső rendszerhez (Steamhez) integrációnk.
            foreach (var item in request.Items)
            {
                var inventoryItem = await userInventoryRepository.GetById(item);

                if(inventoryItem != null) {
                    await userInventoryRepository.DeleteAsync(inventoryItem);
                }
            }

            return new ActionStatus { Status = "OK", Message = "A tárgyak sikeresen ki lettek kérve." };
        }

        /// <inheritdoc/>
        public async Task<ActionStatus> GetItemsAsync()
        {
            var items = await itemRepository.GetAllItemsAsync();

            return new ActionStatus { Status = "OK", Message = items };
        }

        private double GetItemUpgradeSuccessChance(decimal currentValue, Item nextItem)
        {
            // Alap esély
            double baseChance = 0.8;

            // Érték szerinti esély
            double valueMultiplier = 0.05 * Math.Abs((double)(nextItem.ItemValue - currentValue)!) / 10;

            double successChance = Math.Max(0, Math.Min(1, Math.Round(baseChance - valueMultiplier, 2)));

            return successChance;
        }

        private static readonly Dictionary<string, List<byte[]>> _fileSignatures = new()
        {
            { ".gif", new List<byte[]> { new byte[] { 0x47, 0x49, 0x46, 0x38 } } },
            { ".png", new List<byte[]> { new byte[] { 0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A } } },
            { ".jpeg", new List<byte[]>
                {
                    new byte[] { 0xFF, 0xD8, 0xFF, 0xE0 },
                    new byte[] { 0xFF, 0xD8, 0xFF, 0xE2 },
                    new byte[] { 0xFF, 0xD8, 0xFF, 0xE3 },
                    new byte[] { 0xFF, 0xD8, 0xFF, 0xEE },
                    new byte[] { 0xFF, 0xD8, 0xFF, 0xDB },
                }
            },
            { ".jpeg2000", new List<byte[]> { new byte[] { 0x00, 0x00, 0x00, 0x0C, 0x6A, 0x50, 0x20, 0x20, 0x0D, 0x0A, 0x87, 0x0A } } },

            { ".jpg", new List<byte[]>
                {
                    new byte[] { 0xFF, 0xD8, 0xFF, 0xE0 },
                    new byte[] { 0xFF, 0xD8, 0xFF, 0xE1 },
                    new byte[] { 0xFF, 0xD8, 0xFF, 0xE8 },
                    new byte[] { 0xFF, 0xD8, 0xFF, 0xEE },
                    new byte[] { 0xFF, 0xD8, 0xFF, 0xDB },
                }
            }
        };

        private static double GetRandomDouble()
        {
            byte[] bytes = new byte[8];
            using (RandomNumberGenerator rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(bytes);
            }

            long longValue = BitConverter.ToInt64(bytes, 0);
            return (double)longValue / long.MaxValue;
        }

        private async Task<bool> IsCredentialIdUniqueToUser(IsCredentialIdUniqueToUserParams credentialIdUserParams, CancellationToken cancellationToken)
        {
            return !await userRepository.CredentialIdExistsAsync(Convert.ToBase64String(credentialIdUserParams.CredentialId));
        }
    }
}
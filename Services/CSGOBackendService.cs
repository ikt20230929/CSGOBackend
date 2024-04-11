using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using csgo.Models;
using Fido2NetLib;
using Fido2NetLib.Objects;
using KaimiraGames;
using Microsoft.EntityFrameworkCore;
using OtpNet;
using static csgo.Dtos;

namespace csgo.Services
{
    /// <summary>
    /// Backend szolgáltatás
    /// </summary>
    /// <param name="context">Az adatbázis kontextus</param>
    /// <param name="fido2">A Fido2 szolgáltatás</param>
    public class CSGOBackendService(CsgoContext context, IFido2 fido2) : ICsgoBackendService
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

            await context.Items.AddAsync(@case);
            await context.SaveChangesAsync();

            return new ActionStatus { Status = "OK", Message = @case.ToCaseDto([]) };
        }

        /// <inheritdoc/>
        public async Task<ActionStatus> AddCaseItemAsync(int caseId, int itemId)
        {
            var @case = await context.Items.FirstOrDefaultAsync(x => x.ItemType == ItemType.Case && x.ItemId == caseId);
            var item = await context.Items.FirstOrDefaultAsync(x => x.ItemType == ItemType.Item && x.ItemId == itemId);

            if (@case == null) return new ActionStatus { Status = "ERR", Message = "A megadott láda nem található." };
            if (item == null) return new ActionStatus { Status = "ERR", Message = "A megadott tárgy nem található." };

            await context.CaseItems.AddAsync(new CaseItem
            {
                CaseId = @case.ItemId,
                ItemId = item.ItemId
            });
            await context.SaveChangesAsync();

            var caseItems = await context.CaseItems.Where(x => x.Case == @case).Select(x => x.Item.ToDto()).ToListAsync();

            return new ActionStatus { Status = "OK", Message = @case.ToCaseDto(caseItems) };
        }

        /// <inheritdoc/>
        public async Task<ActionStatus> AddGiveawayAsync(GiveawayRecord details)
        {
            var item = await context.Items.FindAsync(details.ItemId);
            if (item == null) return new ActionStatus { Status = "ERR", Message = "A megadott tárgy nem található." };

            var giveaway = new Giveaway
            {
                ItemId = item.ItemId,
                GiveawayDate = details.Date.ToLocalTime(),
                GiveawayDescription = details.Description,
                GiveawayName = details.Name,
            };

            await context.Giveaways.AddAsync(giveaway);
            await context.SaveChangesAsync();

            return new ActionStatus
            {
                Status = "OK",
                Message = new CurrentGiveawayResponse
                {
                    GiveawayDate = giveaway.GiveawayDate,
                    GiveawayDescription = giveaway.GiveawayDescription,
                    GiveawayId = giveaway.GiveawayId,
                    GiveawayItem = giveaway.Item!.ItemName,
                    GiveawayName = giveaway.GiveawayName
                }
            };
        }

        /// <inheritdoc/>
        public async Task<ActionStatus> AddInventoryItemAsync(int userId, int itemId)
        {
            var target = await context.Users.FirstOrDefaultAsync(x => x.UserId == userId);
            var item = await context.Items.FirstOrDefaultAsync(x => x.ItemId == itemId && x.ItemType == ItemType.Item);

            if (target == null) return new ActionStatus { Status = "ERR", Message = "A megadott felhasználó nem található." };
            if (item == null) return new ActionStatus { Status = "ERR", Message = "A megadott tárgy nem található." };

            await context.Userinventories.AddAsync(new Userinventory
            {
                UserId = target.UserId,
                ItemId = item.ItemId
            });
            await context.SaveChangesAsync();

            List<InventoryItemResponse> items = await context.Userinventories.Where(x => x.UserId == target.UserId)
                .Select(x => x.Item.ToInventoryItemDto(x.InventoryId))
                .ToListAsync();

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

            await context.Items.AddAsync(item);
            await context.SaveChangesAsync();

            return new ActionStatus { Status = "OK", Message = item.ToDto() };
        }

        /// <inheritdoc/>
        public async Task<ActionStatus> CheckTotpTokenAsync(User user, EnableTOTPRequest request)
        {
            if (user.TotpEnabled) return new ActionStatus { Status = "ERR", Message = "A kétlépcsős azonosítás már engedélyezve van." };

            var totp = new Totp(Base32Encoding.ToBytes(user.TotpSecret));
            bool verify = totp.VerifyTotp(request.Code, out _, VerificationWindow.RfcSpecifiedNetworkDelay);

            if (verify)
            {
                user.TotpEnabled = true;
                await context.SaveChangesAsync();
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
            if (user.LastClaimDate.Date == DateTime.Now.Date) return new ActionStatus { Status = "ERR", Message = "A napi jutalom már igényelve lett." };

            // Ha az utolsó kérés dátuma nem az aktuális hónapban van, akkor a streaket nullázni kell.
            if (user.LastClaimDate.Month != DateTime.Now.Month) user.LoginStreak = 1;

            int reward = 5;

            if (user.LastClaimDate.Date.AddDays(1) == DateTime.Now.Date)
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

            user.LastClaimDate = DateTime.Now;
            user.Balance += reward;

            await context.SaveChangesAsync();

            return new ActionStatus { Status = "OK", Message = reward };
        }

        /// <inheritdoc/>
        public async Task<ActionStatus> DeleteCaseAsync(int caseId)
        {
            var @case = await context.Items.FirstOrDefaultAsync(x => x.ItemId == caseId && x.ItemType == ItemType.Case);

            if (@case == null) return new ActionStatus { Status = "ERR", Message = "A megadott láda nem található." };

            var inventoryItems = await context.Userinventories.Where(x => x.ItemId == @case.ItemId).ToListAsync();

            foreach (var item in inventoryItems)
            {
                context.Userinventories.Remove(item);
            }

            context.Items.Remove(@case);
            await context.SaveChangesAsync();

            return new ActionStatus { Status = "OK", Message = "A láda sikeresen törölve lett." };
        }

        /// <inheritdoc/>
        public async Task<ActionStatus> DeleteCaseItemAsync(int caseId, int itemId)
        {
            var @case = await context.Items.FindAsync(caseId);
            var item = await context.Items.FindAsync(itemId);

            if (@case == null) return new ActionStatus { Status = "ERR", Message = "A megadott láda nem található." };
            if (item == null) return new ActionStatus { Status = "ERR", Message = "A megadott tárgy nem található." };

            var caseItem = await context.CaseItems.FindAsync(caseId, itemId);
            if (caseItem == null) return new ActionStatus { Status = "ERR", Message = "A megadott tárgy nem található a ládában." };

            context.CaseItems.Remove(caseItem);
            await context.SaveChangesAsync();

            var caseItems = await context.CaseItems.Where(x => x.Case == @case).Select(x => x.Item.ToDto()).ToListAsync();

            return new ActionStatus { Status = "OK", Message = @case.ToCaseDto(caseItems) };
        }

        /// <inheritdoc/>
        public async Task<ActionStatus> DeleteGiveawayAsync(int giveawayId)
        {
            var giveaway = await context.Giveaways.FindAsync(giveawayId);

            if (giveaway == null) return new ActionStatus { Status = "ERR", Message = "A megadott nyereményjáték nem található." };

            var participants = await context.Users.Include(x => x.Giveaways).Where(x => x.Giveaways.Contains(giveaway)).ToListAsync();

            foreach (var item in participants)
            {
                item.Giveaways.Remove(giveaway);
            }

            context.Giveaways.Remove(giveaway);

            await context.SaveChangesAsync();

            return new ActionStatus { Status = "OK", Message = "A nyereményjáték sikeresen törölve lett." };
        }

        /// <inheritdoc/>
        public async Task<ActionStatus> DeleteInventoryItemAsync(int userId, int itemId)
        {
            var target = await context.Users.FirstOrDefaultAsync(x => x.UserId == userId);
            var item = await context.Items.FirstOrDefaultAsync(x => x.ItemId == itemId && x.ItemType == ItemType.Item);
            if (target == null) return new ActionStatus { Status = "ERR", Message = "A megadott felhasználó nem található." };
            if (item == null) return new ActionStatus { Status = "ERR", Message = "A megadott tárgy nem található." };

            var userInventory = await context.Userinventories.FirstOrDefaultAsync(x => x.UserId == target.UserId && x.ItemId == item.ItemId);
            if (userInventory == null) return new ActionStatus { Status = "ERR", Message = "A megadott tárgy nem található a felhasználó leltárában." };

            context.Userinventories.Remove(userInventory);
            await context.SaveChangesAsync();

            List<InventoryItemResponse> items = await context.Userinventories.Where(x => x.UserId == target.UserId).Select(x => x.Item.ToInventoryItemDto(x.InventoryId)).ToListAsync();

            return new ActionStatus { Status = "OK", Message = items };
        }

        /// <inheritdoc/>
        public async Task<ActionStatus> DeleteItemAsync(int itemId)
        {
            var item = await context.Items.FirstOrDefaultAsync(x => x.ItemId == itemId && x.ItemType == ItemType.Item);

            if (item == null) return new ActionStatus { Status = "ERR", Message = "A megadott tárgy nem található." };

            var inventories = await context.Userinventories.Where(x => x.ItemId == itemId).ToListAsync();

            foreach (var inventoryItem in inventories)
            {
                context.Userinventories.Remove(inventoryItem);
            }

            context.Items.Remove(item);
            await context.SaveChangesAsync();

            return new ActionStatus { Status = "OK", Message = "A tárgy sikeresen törölve lett." };
        }

        /// <inheritdoc/>
        public async Task<ActionStatus> DepositAsync(User user, double amount)
        {
            if (amount <= 0) return new ActionStatus { Status = "ERR", Message = "Az összeg nem lehet negatív." };

            user.Balance += amount;
            await context.SaveChangesAsync();

            return new ActionStatus { Status = "OK", Message = $"Sikeresen befizetve: ${amount}." };
        }

        /// <inheritdoc/>
        public async Task<ActionStatus> DisableTotpAsync(User user, DisableTOTPRequest request)
        {
            if (!user.TotpEnabled) return new ActionStatus { Status = "ERR", Message = "A kétlépcsős azonosítás nincs engedélyezve." };

            if (!BCrypt.Net.BCrypt.Verify(request.Password, user.PasswordHash)) return new ActionStatus { Status = "ERR", Message = "Érvénytelen jelszó." };

            var totp = new Totp(Base32Encoding.ToBytes(user.TotpSecret));
            bool verify = totp.VerifyTotp(request.Code, out _, VerificationWindow.RfcSpecifiedNetworkDelay);

            if (verify)
            {
                user.TotpEnabled = false;
                await context.SaveChangesAsync();
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
            await context.SaveChangesAsync();

            return new ActionStatus { Status = "OK", Message = user.TotpSecret };
        }

        /// <inheritdoc/>
        public async Task<ActionStatus> GetCasesAsync()
        {
            var items = await context.Items
                .Where(x => x.ItemType == ItemType.Case)
                .ToListAsync();

            var caseDtos = new List<CaseResponse>();

            foreach (var item in items)
            {
                var caseItems = await context.CaseItems
                    .Where(y => y.CaseId == item.ItemId)
                    .Select(z => z.Item)
                    .Select(z => z.ToDto())
                    .ToListAsync();

                var caseDto = item.ToCaseDto(caseItems);
                caseDtos.Add(caseDto);
            }

            return new ActionStatus { Status = "OK", Message = caseDtos };
        }

        /// <inheritdoc/>
        public async Task<ActionStatus> GetGiveawaysAsync(User user)
        {
            var giveaways = await context.Giveaways.Where(x => x.GiveawayDate > DateTime.Now).Include(x => x.Item).Include(x => x.Users).ToListAsync();

            var mapped = giveaways.Select(giveaway => new CurrentGiveawayResponse
            {
                GiveawayId = giveaway.GiveawayId,
                GiveawayName = giveaway.GiveawayName,
                GiveawayDescription = giveaway.GiveawayDescription!,
                GiveawayDate = giveaway.GiveawayDate,
                GiveawayItem = giveaway.Item!.ItemName,
                GiveawayJoined = giveaway.Users.Contains(user)
            }).ToList();

            return new ActionStatus { Status = "OK", Message = mapped };
        }

        /// <inheritdoc/>
        public async Task<ActionStatus> GetInventoryAsync(User user)
        {
            List<InventoryItemResponse> items = await context.Userinventories.Where(x => x.UserId == user.UserId).Select(x => x.Item.ToInventoryItemDto(x.InventoryId)).ToListAsync();

            return new ActionStatus { Status = "OK", Message = items };
        }

        /// <inheritdoc/>
        public async Task<ActionStatus> GetPastGiveawaysAsync()
        {
            var giveaways = await context.Giveaways
                .Where(x => x.GiveawayDate <= DateTime.Now && x.WinnerUserId != null)
                .Include(x => x.Item).Include(giveaway => giveaway.WinnerUser).ToListAsync();

            var mapped = giveaways.Select(giveaway => new PastGiveawayResponse
            {
                GiveawayDescription = giveaway.GiveawayDescription,
                GiveawayItem = giveaway.Item?.ItemName,
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
            foreach (var item in request.Items)
            {
                if (!await context.Userinventories.AnyAsync(x => x.InventoryId == item && x.UserId == user.UserId)) return new ActionStatus { Status = "ERR", Message = "A megadott tárgy nem található a leltárban." };
            }

            List<InventoryItemResponse> itemData = request.Items.Select(x => context.Userinventories.Include(y => y.Item).First(y => y.InventoryId == x).Item.ToInventoryItemDto(x)).ToList();

            var totalValue = itemData.Sum(x => x.ItemValue);

            var upgradeItems = await context.Items
                .Where(x => x.ItemValue >= totalValue && x.ItemType == ItemType.Item)
                .OrderBy(x => x.ItemValue)
                .ToListAsync();

            if (upgradeItems.Count == 0) return new ActionStatus { Status = "ERR", Message = "A tárgy nem fejleszthető tovább." };

            return new ActionStatus { Status = "OK", Message = upgradeItems.Where(y => GetItemUpgradeSuccessChance(totalValue, y) > 0).Select(x => new { Item = x.ToDto(), Chance = GetItemUpgradeSuccessChance(totalValue, x), Multiplier = Math.Round((decimal)x.ItemValue! / totalValue, 2) }) };
        }

        /// <inheritdoc/>
        public async Task<ActionStatus> GetUserAsync(string username)
        {
            User? user = await context.Users.FirstOrDefaultAsync(x => x.Username == username);

            if (user == null)
            {
                return new ActionStatus { Status = "ERR", Message = "A felhasználó nem található." };
            }

            return new ActionStatus { Status = "OK", Message = user };
        }

        /// <inheritdoc/>
        public async Task<ActionStatus> GetUsersAsync()
        {
            var users = await context.Users.ToListAsync();

            var userDtos = new List<UserResponse>();

            foreach (var u in users)
            {
                var items = await context.Userinventories.Where(x => x.UserId == u.UserId).Select(x => x.Item.ToDto()).ToListAsync();
                userDtos.Add(u.ToDto(items));
            }

            return new ActionStatus { Status = "OK", Message = userDtos };
        }

        /// <inheritdoc/>
        public async Task<ActionStatus> JoinGiveawayAsync(User user, int id)
        {
            var giveaway = await context.Giveaways.Where(x => x.GiveawayDate > DateTime.Now && x.GiveawayId == id).Include(x => x.Users).FirstOrDefaultAsync();
            if (giveaway == null) return new ActionStatus { Status = "ERR", Message = "A megadott nyereményjáték nem található." };
            if (giveaway.Users.Contains(user)) return new ActionStatus { Status = "ERR", Message = "Már csatlakoztál a nyereményjátékhoz." };

            giveaway.Users.Add(user);
            await context.SaveChangesAsync();

            return new ActionStatus { Status = "OK", Message = "Sikeresen csatlakoztál a nyereményjátékhoz." };
        }

        /// <inheritdoc/>
        public async Task<ActionStatus> LoginUserAsync(LoginRequest login, string? jsonOptions = null)
        {
            var request = await GetUserAsync(login.Username);
            if (request.Status == "ERR") return request;

            User storedUser = request.Message!;

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
                        if (!storedUser.TotpEnabled) return new ActionStatus { Status = "ERR", Message = "InvalidMFAMethod" };
                        if (login.Mfa.TotpToken == null) return new ActionStatus { Status = "ERR", Message = "InvalidTotp" };
                        var totp = new Totp(Base32Encoding.ToBytes(storedUser.TotpSecret));
                        bool verify = totp.VerifyTotp(login.Mfa.TotpToken, out _,
                            VerificationWindow.RfcSpecifiedNetworkDelay);
                        return verify ? CheckPassword(login.Password, storedUser) : new ActionStatus { Status = "ERR", Message = "InvalidTotp" };
                    }
                case MfaType.WebAuthnOptions:
                    {
                        if (!storedUser.WebauthnEnabled) return new ActionStatus { Status = "ERR", Message = "InvalidMFAMethod" };
                        if (storedUser.WebauthnCredentialId == null || storedUser.WebauthnPublicKey == null) return new ActionStatus { Status = "ERR", Message = "InvalidWebAuthn" };

                        var credential = JsonSerializer.Deserialize<StoredCredential>(storedUser.WebauthnPublicKey);

                        if (credential == null) return new ActionStatus { Status = "ERR", Message = "InvalidWebAuthn" };

                        var options = fido2.GetAssertionOptions([credential.Descriptor], UserVerificationRequirement.Discouraged);

                        return new ActionStatus { Status = "UI", Message = options.ToJson() };
                    }
                case MfaType.WebAuthnAssertion:
                    {
                        if (!storedUser.WebauthnEnabled) return new ActionStatus { Status = "ERR", Message = "InvalidMFAMethod" };
                        if (storedUser.WebauthnCredentialId == null || storedUser.WebauthnPublicKey == null || login.Mfa.WebAuthnAssertationResponse == null) return new ActionStatus { Status = "ERR", Message = "InvalidWebAuthn" };

                        var options = AssertionOptions.FromJson(jsonOptions);
                        var credential = JsonSerializer.Deserialize<StoredCredential>(storedUser.WebauthnPublicKey);

                        if (credential == null) return new ActionStatus { Status = "ERR", Message = "InvalidWebAuthn" };

                        var result = await fido2.MakeAssertionAsync(
                            login.Mfa.WebAuthnAssertationResponse,
                            options,
                            credential.PublicKey,
                            credential.DevicePublicKeys,
                            credential.SignCount,
                            IsUserHandleOwnerOfCredentialId);

                        if (result.Status != "ok") return new ActionStatus { Status = "ERR", Message = "InvalidWebAuthn" };

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
                        await context.SaveChangesAsync();

                        return CheckPassword(login.Password, storedUser);
                    }
                default:
                    {
                        return new ActionStatus { Status = "ERR", Message = "InvalidCredential" };
                    }
            }
        }

        private ActionStatus CheckPassword(string password, User storedUser)
        {
            if (!BCrypt.Net.BCrypt.Verify(password, storedUser.PasswordHash))
            {
                return new ActionStatus { Status = "ERR", Message = "InvalidCredential" };
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
                expires: DateTime.Now.AddMinutes(30),
                signingCredentials: Signing.AccessTokenCreds);
            var accessTokenString = new JwtSecurityTokenHandler().WriteToken(accessToken);

            // Refresh token létrehozása
            var refreshToken = new JwtSecurityToken(
                issuer: Globals.Config.BackUrl,
                audience: Globals.Config.BackUrl,
                claims: claims,
                expires: DateTime.Now.AddDays(7),
                signingCredentials: Signing.RefreshTokenCreds);
            var refreshTokenString = new JwtSecurityTokenHandler().WriteToken(refreshToken);

            return (accessTokenString, refreshTokenString);
        }

        private async Task<bool> IsUserHandleOwnerOfCredentialId(IsUserHandleOwnerOfCredentialIdParams arg, CancellationToken cancellationToken)
        {
            var user = await context.Users.FirstAsync(x => x.UserId == Convert.ToInt32(Encoding.UTF8.GetString(arg.UserHandle)), cancellationToken: cancellationToken);

            if (user.WebauthnPublicKey == null) return false;

            var credential = JsonSerializer.Deserialize<StoredCredential>(user.WebauthnPublicKey);

            return credential?.UserHandle.SequenceEqual(arg.UserHandle) ?? false;
        }

        /// <inheritdoc/>
        public async Task<ActionStatus> OpenCaseAsync(User user, int caseId)
        {
            var @case = await context.Items.FirstOrDefaultAsync(x => x.ItemType == ItemType.Case && x.ItemId == caseId);
            if (@case == null) return new ActionStatus { Status = "ERR", Message = "A megadott láda nem található." };

            if ((decimal)user.Balance < @case.ItemValue) return new ActionStatus { Status = "ERR", Message = "Nincs elég egyenleged a láda megnyitásához." };

            var ctxCaseItems = await context.CaseItems.Where(x => x.Case == @case).Include(y => y.Item).ToArrayAsync();

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

            await context.Userinventories.AddAsync(new Userinventory
            {
                ItemId = resultItem.ItemId,
                UserId = user.UserId
            });

            user.Balance -= Convert.ToDouble(@case.ItemValue);

            await context.SaveChangesAsync();

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

            if (await context.Users.AnyAsync(u => u.Username == register.Username))
            {
                return new ActionStatus { Status = "ERR", Message = "A megadott felhasználónév már foglalt." };
            }

            if (await context.Users.AnyAsync(u => u.Email == register.Email))
            {
                return new ActionStatus { Status = "ERR", Message = "Az megadott e-mail már használatban van." };
            }

            string hashedPassword = BCrypt.Net.BCrypt.HashPassword(register.Password);
            newUser.PasswordHash = hashedPassword;
            await context.Users.AddAsync(newUser);
            await context.SaveChangesAsync();

            return new ActionStatus { Status = "OK", Message = "Sikeres regisztráció!" };
        }

        /// <inheritdoc/>
        public async Task<ActionStatus> SellItemAsync(User user, int inventoryId)
        {
            var inventoryItem = await context.Userinventories.Include(x => x.Item).FirstOrDefaultAsync(x => x.InventoryId == inventoryId && x.UserId == user.UserId);
            if (inventoryItem == null) return new ActionStatus { Status = "ERR", Message = "A megadott tárgy nem található a leltárban." };

            user.Balance += Convert.ToDouble(inventoryItem.Item.ItemValue);
            context.Userinventories.Remove(inventoryItem);
            await context.SaveChangesAsync();

            return new ActionStatus { Status = "OK", Message = "A tárgy sikeresen eladva." };
        }

        /// <inheritdoc/>
        public async Task<ActionStatus> UpdateCaseAsync(int caseId, CaseRecord details)
        {
            var @case = await context.Items.FirstOrDefaultAsync(x => x.ItemId == caseId && x.ItemType == ItemType.Case);
            if (@case == null) return new ActionStatus { Status = "ERR", Message = "A megadott láda nem található." };

            @case.ItemName = details.Name;
            @case.ItemValue = details.Value;
            if (details.AssetUrl != null) @case.ItemAssetUrl = details.AssetUrl;

            await context.SaveChangesAsync();

            var caseItems = await context.CaseItems.Where(x => x.Case == @case).Select(x => x.Item.ToDto()).ToListAsync();

            return new ActionStatus { Status = "OK", Message = @case.ToCaseDto(caseItems) };
        }

        /// <inheritdoc/>
        public async Task<ActionStatus> UpdateGiveawayAsync(int giveawayId, GiveawayRecord details)
        {
            var giveaway = await context.Giveaways.FindAsync(giveawayId);
            if (giveaway == null) return new ActionStatus { Status = "ERR", Message = "A megadott nyereményjáték nem található." };
            if (giveaway.GiveawayDate < DateTime.Now) return new ActionStatus { Status = "ERR", Message = "Lefutott nyereményjátékot nem lehet módosítani." };
            if (details.Date < DateTime.Now) return new ActionStatus { Status = "ERR", Message = "A nyereményjáték dátuma nem lehet a múltban." };

            var item = await context.Items.FindAsync(details.ItemId);
            if (item == null) return new ActionStatus { Status = "ERR", Message = "A megadott tárgy nem található." };

            giveaway.GiveawayDate = details.Date.ToLocalTime();
            giveaway.GiveawayDescription = details.Description;
            giveaway.GiveawayName = details.Name;
            giveaway.ItemId = item.ItemId;

            await context.SaveChangesAsync();

            return new ActionStatus
            {
                Status = "OK",
                Message = new CurrentGiveawayResponse
                {
                    GiveawayDate = giveaway.GiveawayDate,
                    GiveawayDescription = giveaway.GiveawayDescription,
                    GiveawayId = giveaway.GiveawayId,
                    GiveawayItem = giveaway.Item!.ItemName,
                    GiveawayName = giveaway.GiveawayName
                }
            };
        }

        /// <inheritdoc/>
        public async Task<ActionStatus> UpdateItemAsync(int itemId, ItemRecord details)
        {
            var item = await context.Items.FirstOrDefaultAsync(x => x.ItemId == itemId && x.ItemType == ItemType.Item);
            if (item == null) return new ActionStatus { Status = "ERR", Message = "A megadott tárgy nem található." };

            item.ItemName = details.Name;
            item.ItemDescription = details.Description;
            item.ItemRarity = details.Rarity;
            item.ItemSkinName = details.SkinName;
            item.ItemValue = details.Value;
            if (details.AssetUrl != null) item.ItemAssetUrl = details.AssetUrl;

            await context.SaveChangesAsync();

            return new ActionStatus { Status = "OK", Message = item.ToDto() };
        }

        /// <inheritdoc/>
        public async Task<ActionStatus> UpdateUserAsync(int userId, UserEditRecord details)
        {
            var target = await context.Users.FirstOrDefaultAsync(x => x.UserId == userId);
            if (target == null) return new ActionStatus { Status = "ERR", Message = "A megadott felhasználó nem található." };

            if (await context.Users.AnyAsync(x => x.Username == details.Username && x.UserId != userId)) return new ActionStatus { Status = "ERR", Message = "A megadott felhasználónév már foglalt." };
            if (await context.Users.AnyAsync(x => x.Email == details.Email && x.UserId != userId)) return new ActionStatus { Status = "ERR", Message = "Az megadott e-mail már használatban van." };

            target.Username = details.Username;
            target.Email = details.Email;
            target.Balance = details.Balance;

            await context.SaveChangesAsync();

            var items = await context.Userinventories.Where(x => x.UserId == target.UserId).Select(x => x.Item.ToDto()).ToListAsync();
            return new ActionStatus { Status = "OK", Message = target.ToDto(items) };
        }

        /// <inheritdoc/>
        public async Task<ActionStatus> UpgradeItemAsync(User user, ItemUpgradeRequest request)
        {
            foreach (var item in request.Items)
            {
                if (!await context.Userinventories.AnyAsync(x => x.InventoryId == item && x.UserId == user.UserId)) return new ActionStatus { Status = "ERR", Message = "A megadott tárgy nem található a leltárban." };
            }

            List<InventoryItemResponse> itemData = request.Items.Select(x => context.Userinventories.Include(y => y.Item).First(y => y.InventoryId == x).Item.ToInventoryItemDto(x)).ToList();

            var nextItem = await context.Items.FirstOrDefaultAsync(x => x.ItemId == request.Target && x.ItemType == ItemType.Item);
            if (nextItem == null) return new ActionStatus { Status = "ERR", Message = "A megadott tárgy nem található." };

            var totalValue = itemData.Sum(x => x.ItemValue);

            var chance = GetItemUpgradeSuccessChance(totalValue, nextItem);

            if (GetRandomDouble() < chance)
            {
                foreach (var item in itemData)
                {
                    context.Userinventories.Remove(await context.Userinventories.FirstAsync(x => x.InventoryId == item.InventoryId));
                }
                await context.Userinventories.AddAsync(new Userinventory
                {
                    ItemId = nextItem.ItemId,
                    UserId = user.UserId
                });
                await context.SaveChangesAsync();

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
                    context.Userinventories.Remove(await context.Userinventories.FirstAsync(x => x.InventoryId == item.InventoryId));
                }
                await context.SaveChangesAsync();

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
                                RegDate = DateTime.Now,
                                AaGuid = fidoCredentials.Result.AaGuid
                            };

                            user.WebauthnCredentialId = Convert.ToBase64String(fidoCredentials.Result.Id);
                            user.WebauthnPublicKey = JsonSerializer.Serialize(storedCredential);
                            user.WebauthnEnabled = true;

                            await context.SaveChangesAsync();

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
        public async Task<ActionStatus> WithdrawItemsAsync(User user, ItemWithdrawRequest request)
        {
            foreach (var item in request.Items)
            {
                var inventoryItem = await context.Userinventories.Include(x => x.Item).FirstOrDefaultAsync(x => x.InventoryId == item && x.UserId == user.UserId);
                if (inventoryItem == null) return new ActionStatus { Status = "ERR", Message = "A megadott tárgy nem található a leltárban." };
            }

            // Valójában csak kitöröljük a tárgyakat a leltárból, mert nincs külső rendszerhez (Steamhez) integrációnk.
            foreach (var item in request.Items)
            {
                var inventoryItem = await context.Userinventories.Include(x => x.Item).FirstAsync(x => x.InventoryId == item && x.UserId == user.UserId);
                context.Userinventories.Remove(inventoryItem);
            }

            await context.SaveChangesAsync();

            return new ActionStatus { Status = "OK", Message = "A tárgyak sikeresen ki lettek kérve." };
        }

        /// <inheritdoc/>
        public async Task<ActionStatus> GetItemsAsync()
        {
            var items = await context.Items.Where(x => x.ItemType == ItemType.Item).Select(x => x.ToDto()).ToListAsync();

            return new ActionStatus { Status = "OK", Message = items };
        }

        private double GetItemUpgradeSuccessChance(decimal currentValue, Item nextItem)
        {
            var next = context.Items.Find(nextItem.ItemId);

            // Alap esély
            double baseChance = 0.8;

            // Érték szerinti esély
            double valueMultiplier = 0.05 * Math.Abs((double)(next!.ItemValue - currentValue)!) / 10;

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
            return !await context.Users.AnyAsync(x => x.WebauthnCredentialId == Convert.ToBase64String(credentialIdUserParams.CredentialId), cancellationToken: cancellationToken);
        }
    }
}
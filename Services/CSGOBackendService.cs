using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.Text.Json;
using csgo.Models;
using Fido2NetLib;
using Fido2NetLib.Objects;
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
        /// <inheritdoc/>
        public async Task<ActionStatus> AddCaseAsync(CaseRecord details)
        {
            
        }

        /// <inheritdoc/>
        public async Task<ActionStatus> AddCaseItemAsync(int caseId, int itemId)
        {
            
        }

        /// <inheritdoc/>
        public async Task<ActionStatus> AddGiveawayAsync(GiveawayRecord details)
        {
            
        }

        /// <inheritdoc/>
        public async Task<ActionStatus> AddInventoryItemAsync(int userId, int itemId)
        {
            
        }

        /// <inheritdoc/>
        public async Task<ItemResponse> AddItemAsync(ItemRecord details)
        {
            
        }

        /// <inheritdoc/>
        public async Task<ActionStatus> CheckTotpTokenAsync(User user, EnableTOTPRequest request)
        {
            
        }

        /// <inheritdoc/>
        public async Task<ActionStatus> ClaimDailyRewardAsync(User user)
        {
            
        }

        /// <inheritdoc/>
        public async Task<ActionStatus> DeleteCaseAsync(int caseId)
        {
            
        }

        /// <inheritdoc/>
        public async Task<ActionStatus> DeleteCaseItemAsync(int caseId, int itemId)
        {
            
        }

        /// <inheritdoc/>
        public async Task<ActionStatus> DeleteGiveawayAsync(int giveawayId)
        {
            
        }

        /// <inheritdoc/>
        public async Task<ActionStatus> DeleteInventoryItemAsync(int userId, int itemId)
        {
            
        }

        /// <inheritdoc/>
        public async Task<ActionStatus> DeleteItemAsync(int itemId)
        {
            
        }

        /// <inheritdoc/>
        public async Task<ActionStatus> DepositAsync(User user, double amount)
        {
            
        }

        /// <inheritdoc/>
        public async Task<ActionStatus> DisableTotpAsync(User user, DisableTOTPRequest request)
        {
            
        }

        /// <inheritdoc/>
        public async Task<ActionStatus> GenerateTotpTokenAsync(User user)
        {
            
        }

        /// <inheritdoc/>
        public async Task<List<CaseResponse>> GetCasesAsync()
        {
            
        }

        /// <inheritdoc/>
        public async Task<List<CurrentGiveawayResponse>> GetGiveawaysAsync()
        {
            
        }

        /// <inheritdoc/>
        public async Task<List<InventoryItemResponse>> GetInventoryAsync(User user)
        {
            
        }

        /// <inheritdoc/>
        public async Task<List<PastGiveawayResponse>> GetPastGiveawaysAsync()
        {
            
        }

        /// <inheritdoc/>
        public async Task<UserResponse> GetProfileAsync(User user)
        {
            
        }

        /// <inheritdoc/>
        public async Task<ActionStatus> GetUpgradeItemsAsync(ItemUpgradeListRequest request)
        {
            
        }

        /// <inheritdoc/>
        public async Task<ActionStatus> GetUserAsync(string username)
        {
            User user = await context.Users.FirstAsync(x => x.Username == username);

            if (user == null)
            {
                return new ActionStatus { Status = "ERR", Message = "A felhasználó nem található." };
            }

            return new ActionStatus { Status = "OK", Message = user };
        }

        /// <inheritdoc/>
        public async Task<List<UserResponse>> GetUsersAsync()
        {
            
        }

        /// <inheritdoc/>
        public async Task<ActionStatus> JoinGiveawayAsync(User user, int id)
        {
            
        }

        /// <inheritdoc/>
        public async Task<ActionStatus> LoginUserAsync(LoginRequest login, string? jsonOptions = null)
        {
            User storedUser = (await GetUserAsync(login.Username)).Message!;

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
                return new ActionStatus { Status = "ERR", Message = "InvalidCredentials" };
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
            
        }

        /// <inheritdoc/>
        public async Task<ActionStatus> UpdateCaseAsync(int caseId, CaseRecord details)
        {
            
        }

        /// <inheritdoc/>
        public async Task<ActionStatus> UpdateGiveawayAsync(int giveawayId, GiveawayRecord details)
        {
            
        }

        /// <inheritdoc/>
        public async Task<ActionStatus> UpdateItemAsync(int itemId, ItemRecord details)
        {
            
        }

        /// <inheritdoc/>
        public async Task<ActionStatus> UpdateUserAsync(int userId, UserEditRecord details)
        {
            
        }

        /// <inheritdoc/>
        public async Task<ActionStatus> UpgradeItemAsync(User user, ItemUpgradeRequest request)
        {
            
        }

        /// <inheritdoc/>
        public async Task<ActionStatus> UploadImageAsync(IFormFile image)
        {

        }
        
        /// <inheritdoc/>
        public Task<ActionStatus> WebAuthnAttestationAsync(WebauthnAttestationRequest details)
        {
            throw new NotImplementedException();
        }

        /// <inheritdoc/>
        public Task<ActionStatus> WithdrawItemsAsync(User user, ItemWithdrawRequest request)
        {
            throw new NotImplementedException();
        }

        /// <inheritdoc/>
        public Task<List<ItemResponse>> GetItemsAsync()
        {
            throw new NotImplementedException();
        }
    }
}
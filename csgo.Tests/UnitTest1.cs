using static csgo.Dtos;
using csgo.Models;
using csgo.Services;
using Fido2NetLib;
using FluentAssertions;
using Moq;
using csgo.Data;
using OtpNet;

namespace csgo.Tests
{
    public class CSGOBackendServiceTests
    {
        private readonly CSGOBackendService _service;
        private readonly Mock<ICaseItemRepository> _caseItemRepository;
        private readonly Mock<IGiveawayRepository> _giveawayRepository;
        private readonly Mock<IItemRepository> _itemRepository;
        private readonly Mock<IUserInventoryRepository> _userInventoryRepository;
        private readonly Mock<IUserRepository> _userRepository;
        private readonly Mock<IDateTimeProvider> _dateTimeProvider;
        private readonly Mock<IPasswordAuthenticationProvider> _passwordAuthenticationProvider;
        private readonly Mock<ITotpProvider> _totpProvider;
        private readonly Mock<IFido2> _mockFido2;

        public CSGOBackendServiceTests()
        {
            _mockFido2 = new Mock<IFido2>();
            _caseItemRepository = MockRepositories.GetMockCaseItemRepository();
            _giveawayRepository = MockRepositories.GetMockGiveawayRepository();
            _itemRepository = MockRepositories.GetMockItemRepository();
            _userInventoryRepository = MockRepositories.GetMockUserInventoryRepository();
            _userRepository = MockRepositories.GetMockUserRepository();
            _dateTimeProvider = MockRepositories.GetMockDateTimeProvider();
            _passwordAuthenticationProvider = MockRepositories.GetMockPasswordAuthenticationProvider();
            _totpProvider = MockRepositories.GetMockTotpProvider();

            _service = new CSGOBackendService(_caseItemRepository.Object, _giveawayRepository.Object, _itemRepository.Object, _userInventoryRepository.Object, _userRepository.Object, _dateTimeProvider.Object, _passwordAuthenticationProvider.Object, _totpProvider.Object, _mockFido2.Object);
        }

        [Fact]
        public async Task AddCaseAsync_ShouldAddCase()
        {
            // Arrange
            var newCase = new CaseRecord("Test Case", (decimal)123.45, "https://test.com");

            // Act
            var result = await _service.AddCaseAsync(newCase);

            // Assert
            result.Should().NotBeNull();
            result.Status.Should().Be("OK");

            var message = (CaseResponse)result.Message;
            message.Should().NotBeNull();
            message.ItemName.Should().Be(newCase.Name);
            message.ItemValue.Should().Be(newCase.Value);
            message.ItemAssetUrl.Should().Be(newCase.AssetUrl);
            message.Items.Should().BeEmpty();

            _itemRepository.Verify(x => x.AddAsync(It.IsAny<Item>()), Times.Once);
        }

        [Fact]
        public async Task AddCaseItemAsync_ShouldAddItemToCase()
        {
            // Act
            var result = await _service.AddCaseItemAsync(2, 1);

            // Assert
            result.Should().NotBeNull();
            result.Status.Should().Be("OK");

            var message = (CaseResponse)result.Message;
            message.Should().NotBeNull();

            _itemRepository.Verify(x => x.GetCaseByIdAsync(It.IsAny<int>()), Times.Once);
            _itemRepository.Verify(x => x.GetItemByIdAsync(It.IsAny<int>()), Times.Once);
            _caseItemRepository.Verify(x => x.AddAsync(It.IsAny<CaseItem>()), Times.Once);
            _caseItemRepository.Verify(x => x.GetCaseItemsAsync(It.IsAny<int>()), Times.Once);
        }

        [Fact]
        public async Task AddCaseItemAsync_ShouldReturnErrorIfItemNotFound()
        {
            // Act
            var result = await _service.AddCaseItemAsync(2, 100);

            // Assert
            result.Should().NotBeNull();
            result.Status.Should().Be("ERR");
            var message = (string)result.Message;
            message.Should().NotBeNull();
            message.Should().Be("A megadott tárgy nem található.");

            _itemRepository.Verify(x => x.GetCaseByIdAsync(It.IsAny<int>()), Times.Once);
            _itemRepository.Verify(x => x.GetItemByIdAsync(It.IsAny<int>()), Times.Once);
        }

        [Fact]
        public async Task AddCaseItemAsync_ShouldReturnErrorIfCaseNotFound()
        {
            // Act
            var result = await _service.AddCaseItemAsync(100, 1);

            // Assert
            result.Should().NotBeNull();
            result.Status.Should().Be("ERR");
            var message = (string)result.Message;
            message.Should().NotBeNull();
            message.Should().Be("A megadott láda nem található.");

            _itemRepository.Verify(x => x.GetCaseByIdAsync(It.IsAny<int>()), Times.Once);
            _itemRepository.Verify(x => x.GetItemByIdAsync(It.IsAny<int>()), Times.Once);
        }

        [Fact]
        public async Task AddGiveawayAsync_ShouldAddGiveaway()
        {
            // Arrange
            var newGiveaway = new GiveawayRecord("Test Giveaway", "Test Description", _dateTimeProvider.Object.Now.AddDays(1), 1);

            // Act
            var result = await _service.AddGiveawayAsync(newGiveaway);

            // Assert
            result.Should().NotBeNull();
            result.Status.Should().Be("OK");

            var message = (CurrentGiveawayResponse)result.Message;
            message.Should().NotBeNull();

            _giveawayRepository.Verify(x => x.AddAsync(It.IsAny<Giveaway>()), Times.Once);
        }

        [Fact]
        public async Task AddGiveawayAsync_ShouldReturnErrorIfItemNotFound()
        {
            // Arrange
            var newGiveaway = new GiveawayRecord("Test Giveaway", "Test Description", _dateTimeProvider.Object.Now.AddDays(1), 100);

            // Act
            var result = await _service.AddGiveawayAsync(newGiveaway);

            // Assert
            result.Should().NotBeNull();
            result.Status.Should().Be("ERR");

            var message = (string)result.Message;
            message.Should().NotBeNull();
            message.Should().Be("A megadott tárgy nem található.");

            _itemRepository.Verify(x => x.GetItemByIdAsync(It.IsAny<int>()), Times.Once);
        }

        [Fact]
        public async Task AddInventoryItemAsync_ShouldAddItemToInventory()
        {
            // Act
            var result = await _service.AddInventoryItemAsync(1, 1);

            // Assert
            result.Should().NotBeNull();
            result.Status.Should().Be("OK");

            var message = (List<InventoryItemResponse>)result.Message;
            message.Should().NotBeNull();
            message.Should().NotBeEmpty();

            _userRepository.Verify(x => x.GetByIdAsync(It.IsAny<int>()), Times.Once);
            _itemRepository.Verify(x => x.GetItemByIdAsync(It.IsAny<int>()), Times.Once);
            _userInventoryRepository.Verify(x => x.AddAsync(It.IsAny<Userinventory>()), Times.Once);
            _userInventoryRepository.Verify(x => x.GetUserInventoryAsync(It.IsAny<int>()), Times.Once);
        }

        [Fact]
        public async Task AddInventoryItemAsync_ShouldReturnErrorIfItemNotFound()
        {
            // Act
            var result = await _service.AddInventoryItemAsync(1, 100);

            // Assert
            result.Should().NotBeNull();
            result.Status.Should().Be("ERR");

            var message = (string)result.Message;
            message.Should().NotBeNull();
            message.Should().Be("A megadott tárgy nem található.");

            _itemRepository.Verify(x => x.GetItemByIdAsync(It.IsAny<int>()), Times.Once);
            _userRepository.Verify(x => x.GetByIdAsync(It.IsAny<int>()), Times.Once);
        }

        [Fact]
        public async Task AddInventoryItemAsync_ShouldReturnErrorIfUserNotFound()
        {
            // Act
            var result = await _service.AddInventoryItemAsync(100, 1);

            // Assert
            result.Should().NotBeNull();
            result.Status.Should().Be("ERR");

            var message = (string)result.Message;
            message.Should().NotBeNull();
            message.Should().Be("A megadott felhasználó nem található.");

            _userRepository.Verify(x => x.GetByIdAsync(It.IsAny<int>()), Times.Once);
            _itemRepository.Verify(x => x.GetItemByIdAsync(It.IsAny<int>()), Times.Once);
        }

        [Fact]
        public async Task AddItemAsync_ShouldAddItem()
        {
            // Arrange
            var newItem = new ItemRecord("Test Item", "Test Description", ItemRarity.CONSUMER_GRADE, "Item Skin", (decimal)123.45, "https://test.com");

            // Act
            var result = await _service.AddItemAsync(newItem);

            // Assert
            result.Should().NotBeNull();
            result.Status.Should().Be("OK");

            var message = (ItemResponse)result.Message;
            message.Should().NotBeNull();
            message.ItemName.Should().Be(newItem.Name);
            message.ItemDescription.Should().Be(newItem.Description);
            message.ItemRarity.Should().Be(newItem.Rarity);
            message.ItemSkinName.Should().Be(newItem.SkinName);
            message.ItemValue.Should().Be(newItem.Value);
            message.ItemAssetUrl.Should().Be(newItem.AssetUrl);
            message.ItemType.Should().Be(ItemType.Item);

            _itemRepository.Verify(x => x.AddAsync(It.IsAny<Item>()), Times.Once);
        }

        [Fact]
        public async Task CheckTotpTokenAsync_ShouldEnableTotpIfTokenIsValid()
        {
            // Arrange
            var user = new User { TotpEnabled = false, TotpSecret = "test" };
            var request = new EnableTOTPRequest("123456");

            // Act
            var result = await _service.CheckTotpTokenAsync(user, request);

            // Assert
            result.Should().NotBeNull();
            result.Status.Should().Be("OK");
            var message = (string)result.Message;
            message.Should().NotBeNull();
            message.Should().Be("A kétlépcsős azonosítás sikeresen engedélyezve lett.");

            _totpProvider.Verify(x => x.VerifyTotp(It.IsAny<byte[]>(), It.IsAny<string>()), Times.Once);
            _userRepository.Verify(x => x.UpdateAsync(It.IsAny<User>()), Times.Once);
        }

        [Fact]
        public async Task CheckTotpTokenAsync_ShouldReturnErrorIfTokenIsInvalid()
        {
            // Arrange
            var user = new User { TotpEnabled = false, TotpSecret = "test" };
            var request = new EnableTOTPRequest("654321");

            // Act
            var result = await _service.CheckTotpTokenAsync(user, request);

            // Assert
            result.Should().NotBeNull();
            result.Status.Should().Be("ERR");
            var message = (string)result.Message;
            message.Should().NotBeNull();
            message.Should().Be("Érvénytelen kód.");

            _totpProvider.Verify(x => x.VerifyTotp(It.IsAny<byte[]>(), It.IsAny<string>()), Times.Once);
            _userRepository.Verify(x => x.UpdateAsync(It.IsAny<User>()), Times.Never);
        }

        [Fact]
        public async Task CheckTotpTokenAsync_ShouldReturnErrorIfTotpIsAlreadyEnabled()
        {
            // Arrange
            var user = new User { TotpEnabled = true, TotpSecret = "test" };
            var request = new EnableTOTPRequest("123456");

            // Act
            var result = await _service.CheckTotpTokenAsync(user, request);

            // Assert
            result.Should().NotBeNull();
            result.Status.Should().Be("ERR");
            var message = (string)result.Message;
            message.Should().NotBeNull();
            message.Should().Be("A kétlépcsős azonosítás már engedélyezve van.");

            _totpProvider.Verify(x => x.VerifyTotp(It.IsAny<byte[]>(), It.IsAny<string>()), Times.Never);
            _userRepository.Verify(x => x.UpdateAsync(It.IsAny<User>()), Times.Never);
        }

        [Theory]
        [InlineData(1, 5)]
        [InlineData(3, 10)]
        [InlineData(7, 15)]
        [InlineData(14, 20)]
        [InlineData(30, 25)]
        public async Task ClaimDailyRewardAsync_ShouldClaimDailyReward(int loginStreak, int expectedReward)
        {
            // Arrange
            var user = new User { LastClaimDate = _dateTimeProvider.Object.Now.AddDays(-1), LoginStreak = loginStreak - 1 };

            // Act
            var result = await _service.ClaimDailyRewardAsync(user);

            // Assert
            result.Should().NotBeNull();
            result.Status.Should().Be("OK");
            var message = (int)result.Message;
            message.Should().Be(expectedReward);

            _userRepository.Verify(x => x.UpdateAsync(It.IsAny<User>()), Times.Once);
        }

        [Fact]
        public async Task ClaimDailyRewardAsync_ShouldResetStreakIfNextMonth()
        {
            // Arrange
            var user = new User { LastClaimDate = _dateTimeProvider.Object.Now.AddMonths(-1), LoginStreak = 30 };

            // Act
            var result = await _service.ClaimDailyRewardAsync(user);

            // Assert
            result.Should().NotBeNull();
            result.Status.Should().Be("OK");
            var message = (int)result.Message;
            message.Should().Be(5);
            user.LoginStreak.Should().Be(1);

            _userRepository.Verify(x => x.UpdateAsync(It.IsAny<User>()), Times.Once);
        }

        [Fact]
        public async Task ClaimDailyRewardAsync_ShouldReturnErrorIfAlreadyClaimed()
        {
            // Arrange
            var user = new User { LastClaimDate = _dateTimeProvider.Object.Now, LoginStreak = 0 };

            // Act
            var result = await _service.ClaimDailyRewardAsync(user);

            // Assert
            result.Should().NotBeNull();
            result.Status.Should().Be("ERR");
            var message = (string)result.Message;
            message.Should().NotBeNull();
            message.Should().Be("A napi jutalom már igényelve lett.");

            _userRepository.Verify(x => x.UpdateAsync(It.IsAny<User>()), Times.Never);
        }

        [Fact]
        public async Task DeleteCaseAsync_ShouldDeleteCase()
        {
            // Act
            var result = await _service.DeleteCaseAsync(2);

            // Assert
            result.Should().NotBeNull();
            result.Status.Should().Be("OK");

            var message = (string)result.Message;
            message.Should().NotBeNull();
            message.Should().Be("A láda sikeresen törölve lett.");
            
            _userInventoryRepository.Verify(x => x.DeleteAsync(It.IsAny<Userinventory>()), Times.Exactly(2));
            _itemRepository.Verify(x => x.DeleteAsync(It.IsAny<Item>()), Times.Once);
        }

        [Fact]
        public async Task DeleteCaseAsync_ShouldReturnErrorIfCaseNotFound()
        {
            // Act
            var result = await _service.DeleteCaseAsync(100);

            // Assert
            result.Should().NotBeNull();
            result.Status.Should().Be("ERR");

            var message = (string)result.Message;
            message.Should().NotBeNull();
            message.Should().Be("A megadott láda nem található.");
            
            _userInventoryRepository.Verify(x => x.DeleteAsync(It.IsAny<Userinventory>()), Times.Never);
            _itemRepository.Verify(x => x.DeleteAsync(It.IsAny<Item>()), Times.Never);
        }

        [Fact]
        public async Task DeleteCaseItemAsync_ShouldDeleteItemFromCase()
        {
            // Act
            var result = await _service.DeleteCaseItemAsync(6, 5);

            // Assert
            result.Should().NotBeNull();
            result.Status.Should().Be("OK");

            var message = (CaseResponse)result.Message;
            message.Should().NotBeNull();
            message.Items.Should().BeEmpty();

            _itemRepository.Verify(x => x.GetCaseByIdAsync(It.IsAny<int>()), Times.Once);
            _itemRepository.Verify(x => x.GetItemByIdAsync(It.IsAny<int>()), Times.Once);
            _caseItemRepository.Verify(x => x.GetCaseItemByIdAsync(It.IsAny<int>(), It.IsAny<int>()), Times.Once);
            _caseItemRepository.Verify(x => x.DeleteAsync(It.IsAny<CaseItem>()), Times.Once);
            _caseItemRepository.Verify(x => x.GetCaseItemsAsync(It.IsAny<int>()), Times.Once);
        }

        [Fact]
        public async Task DeleteCaseItemAsync_ShouldReturnErrorIfCaseNotFound()
        {
            // Act
            var result = await _service.DeleteCaseItemAsync(100, 1);

            // Assert
            result.Should().NotBeNull();
            result.Status.Should().Be("ERR");

            var message = (string)result.Message;
            message.Should().NotBeNull();
            message.Should().Be("A megadott láda nem található.");

            _itemRepository.Verify(x => x.GetCaseByIdAsync(It.IsAny<int>()), Times.Once);
            _itemRepository.Verify(x => x.GetItemByIdAsync(It.IsAny<int>()), Times.Once);
            _caseItemRepository.Verify(x => x.GetCaseItemByIdAsync(It.IsAny<int>(), It.IsAny<int>()), Times.Never);
            _caseItemRepository.Verify(x => x.DeleteAsync(It.IsAny<CaseItem>()), Times.Never);
            _caseItemRepository.Verify(x => x.GetCaseItemsAsync(It.IsAny<int>()), Times.Never);
        }

        [Fact]
        public async Task DeleteCaseItemAsync_ShouldReturnErrorIfItemNotFound()
        {
            // Act
            var result = await _service.DeleteCaseItemAsync(6, 100);

            // Assert
            result.Should().NotBeNull();
            result.Status.Should().Be("ERR");

            var message = (string)result.Message;
            message.Should().NotBeNull();
            message.Should().Be("A megadott tárgy nem található.");

            _itemRepository.Verify(x => x.GetCaseByIdAsync(It.IsAny<int>()), Times.Once);
            _itemRepository.Verify(x => x.GetItemByIdAsync(It.IsAny<int>()), Times.Once);
            _caseItemRepository.Verify(x => x.GetCaseItemByIdAsync(It.IsAny<int>(), It.IsAny<int>()), Times.Never);
            _caseItemRepository.Verify(x => x.DeleteAsync(It.IsAny<CaseItem>()), Times.Never);
            _caseItemRepository.Verify(x => x.GetCaseItemsAsync(It.IsAny<int>()), Times.Never);
        }

        [Fact]
        public async Task DeleteCaseItemAsync_ShouldReturnErrorIfItemNotInCase()
        {
            // Act
            var result = await _service.DeleteCaseItemAsync(6, 1);

            // Assert
            result.Should().NotBeNull();
            result.Status.Should().Be("ERR");

            var message = (string)result.Message;
            message.Should().NotBeNull();
            message.Should().Be("A megadott tárgy nem található a ládában.");

            _itemRepository.Verify(x => x.GetCaseByIdAsync(It.IsAny<int>()), Times.Once);
            _itemRepository.Verify(x => x.GetItemByIdAsync(It.IsAny<int>()), Times.Once);
            _caseItemRepository.Verify(x => x.GetCaseItemByIdAsync(It.IsAny<int>(), It.IsAny<int>()), Times.Once);
            _caseItemRepository.Verify(x => x.DeleteAsync(It.IsAny<CaseItem>()), Times.Never);
            _caseItemRepository.Verify(x => x.GetCaseItemsAsync(It.IsAny<int>()), Times.Never);
        }

        [Fact]
        public async Task DeleteGiveawayAsync_ShouldDeleteGiveaway()
        {
            // Act
            var result = await _service.DeleteGiveawayAsync(1);

            // Assert
            result.Should().NotBeNull();
            result.Status.Should().Be("OK");

            var message = (string)result.Message;
            message.Should().NotBeNull();
            message.Should().Be("A nyereményjáték sikeresen törölve lett.");
            
            _giveawayRepository.Verify(x => x.GetByIdAsync(It.IsAny<int>()), Times.Once);
            _giveawayRepository.Verify(x => x.GetParticipantsAsync(It.IsAny<Giveaway>()), Times.Once);
            _userRepository.Verify(x => x.UpdateAsync(It.IsAny<User>()), Times.Exactly(2));
            _giveawayRepository.Verify(x => x.DeleteAsync(It.IsAny<Giveaway>()), Times.Once);
        }

        [Fact]
        public async Task DeleteGiveawayAsync_ShouldReturnErrorIfGiveawayNotFound()
        {
            // Act
            var result = await _service.DeleteGiveawayAsync(100);

            // Assert
            result.Should().NotBeNull();
            result.Status.Should().Be("ERR");

            var message = (string)result.Message;
            message.Should().NotBeNull();
            message.Should().Be("A megadott nyereményjáték nem található.");
            
            _giveawayRepository.Verify(x => x.GetByIdAsync(It.IsAny<int>()), Times.Once);
            _giveawayRepository.Verify(x => x.GetParticipantsAsync(It.IsAny<Giveaway>()), Times.Never);
            _userRepository.Verify(x => x.UpdateAsync(It.IsAny<User>()), Times.Never);
            _giveawayRepository.Verify(x => x.DeleteAsync(It.IsAny<Giveaway>()), Times.Never);
        }

        [Fact]
        public async Task DeleteInventoryItemAsync_ShouldDeleteItemFromInventory()
        {
            // Act
            var result = await _service.DeleteInventoryItemAsync(1, 1);

            // Assert
            result.Should().NotBeNull();
            result.Status.Should().Be("OK");

            var message = (List<InventoryItemResponse>)result.Message;
            message.Should().NotBeNull();
            message.Should().HaveCount(4);

            _userRepository.Verify(x => x.GetByIdAsync(It.IsAny<int>()), Times.Once);
            _itemRepository.Verify(x => x.GetItemByIdAsync(It.IsAny<int>()), Times.Once);
            _userInventoryRepository.Verify(x => x.GetUserInventoryAsync(It.IsAny<int>()), Times.Once);
            _userInventoryRepository.Verify(x => x.DeleteAsync(It.IsAny<Userinventory>()), Times.Once);
        }

        [Fact]
        public async Task DeleteInventoryItemAsync_ShouldReturnErrorIfItemNotFound()
        {
            // Act
            var result = await _service.DeleteInventoryItemAsync(1, 100);

            // Assert
            result.Should().NotBeNull();
            result.Status.Should().Be("ERR");

            var message = (string)result.Message;
            message.Should().NotBeNull();
            message.Should().Be("A megadott tárgy nem található.");

            _userRepository.Verify(x => x.GetByIdAsync(It.IsAny<int>()), Times.Once);
            _itemRepository.Verify(x => x.GetItemByIdAsync(It.IsAny<int>()), Times.Once);
            _userInventoryRepository.Verify(x => x.GetUserInventoryAsync(It.IsAny<int>()), Times.Never);
            _userInventoryRepository.Verify(x => x.DeleteAsync(It.IsAny<Userinventory>()), Times.Never);
        }

        [Fact]
        public async Task DeleteInventoryItemAsync_ShouldReturnErrorIfUserNotFound()
        {
            // Act
            var result = await _service.DeleteInventoryItemAsync(100, 1);

            // Assert
            result.Should().NotBeNull();
            result.Status.Should().Be("ERR");

            var message = (string)result.Message;
            message.Should().NotBeNull();
            message.Should().Be("A megadott felhasználó nem található.");

            _userRepository.Verify(x => x.GetByIdAsync(It.IsAny<int>()), Times.Once);
            _itemRepository.Verify(x => x.GetItemByIdAsync(It.IsAny<int>()), Times.Once);
            _userInventoryRepository.Verify(x => x.GetUserInventoryAsync(It.IsAny<int>()), Times.Never);
            _userInventoryRepository.Verify(x => x.DeleteAsync(It.IsAny<Userinventory>()), Times.Never);
        }

        [Fact]
        public async Task DeleteInventoryItemAsync_ShouldReturnErrorIfItemNotInInventory()
        {
            // Act
            var result = await _service.DeleteInventoryItemAsync(1, 5);

            // Assert
            result.Should().NotBeNull();
            result.Status.Should().Be("ERR");

            var message = (string)result.Message;
            message.Should().NotBeNull();
            message.Should().Be("A megadott tárgy nem található a felhasználó leltárában.");

            _userRepository.Verify(x => x.GetByIdAsync(It.IsAny<int>()), Times.Once);
            _itemRepository.Verify(x => x.GetItemByIdAsync(It.IsAny<int>()), Times.Once);
            _userInventoryRepository.Verify(x => x.GetUserInventoryAsync(It.IsAny<int>()), Times.Once);
            _userInventoryRepository.Verify(x => x.DeleteAsync(It.IsAny<Userinventory>()), Times.Never);
        }

        [Fact]
        public async Task DeleteItemAsync_ShouldDeleteItem()
        {
            // Act
            var result = await _service.DeleteItemAsync(1);

            // Assert
            result.Should().NotBeNull();
            result.Status.Should().Be("OK");

            var message = (string)result.Message;
            message.Should().NotBeNull();
            message.Should().Be("A tárgy sikeresen törölve lett.");
            
            _itemRepository.Verify(x => x.GetItemByIdAsync(It.IsAny<int>()), Times.Once);
            _userInventoryRepository.Verify(x => x.GetInventoryItemsByItemIdAsync(It.IsAny<int>()), Times.Once);
            _userInventoryRepository.Verify(x => x.DeleteAsync(It.IsAny<Userinventory>()), Times.Exactly(2));
            _itemRepository.Verify(x => x.DeleteAsync(It.IsAny<Item>()), Times.Once);
        }

        [Fact]
        public async Task DeleteItemAsync_ShouldReturnErrorIfItemNotFound()
        {
            // Act
            var result = await _service.DeleteItemAsync(100);

            // Assert
            result.Should().NotBeNull();
            result.Status.Should().Be("ERR");

            var message = (string)result.Message;
            message.Should().NotBeNull();
            message.Should().Be("A megadott tárgy nem található.");
            
            _itemRepository.Verify(x => x.GetItemByIdAsync(It.IsAny<int>()), Times.Once);
            _userInventoryRepository.Verify(x => x.GetInventoryItemsByItemIdAsync(It.IsAny<int>()), Times.Never);
            _userInventoryRepository.Verify(x => x.DeleteAsync(It.IsAny<Userinventory>()), Times.Never);
            _itemRepository.Verify(x => x.DeleteAsync(It.IsAny<Item>()), Times.Never);
        }

        [Fact]
        public async Task DepositAsync_ShouldIncreaseBalance()
        {
            // Arrange
            var user = new User { Balance = 100 };

            // Act
            var result = await _service.DepositAsync(user, 50);

            // Assert
            result.Should().NotBeNull();
            result.Status.Should().Be("OK");

            var message = (string)result.Message;
            message.Should().Be("Sikeresen befizetve: $50.");

            _userRepository.Verify(x => x.UpdateAsync(It.IsAny<User>()), Times.Once);
        }

        [Theory]
        [InlineData(0)]
        [InlineData(-50)]
        public async Task DepositAsync_ShouldReturnErrorIfAmountIsNegativeOrZero(int amount)
        {
            // Arrange
            var user = new User { Balance = 100 };

            // Act
            var result = await _service.DepositAsync(user, amount);

            // Assert
            result.Should().NotBeNull();
            result.Status.Should().Be("ERR");

            var message = (string)result.Message;
            message.Should().Be("Az összeg nem lehet negatív.");

            _userRepository.Verify(x => x.UpdateAsync(It.IsAny<User>()), Times.Never);
        }

        [Fact]
        public async Task DisableTotpAsync_ShouldDisableTotp()
        {
            // Arrange
            var user = new User { TotpEnabled = true, TotpSecret = "test", PasswordHash = "hash" };
            var request = new DisableTOTPRequest("123456", "password");

            // Act
            var result = await _service.DisableTotpAsync(user, request);

            // Assert
            result.Should().NotBeNull();
            result.Status.Should().Be("OK");

            var message = (string)result.Message;
            message.Should().Be("A kétlépcsős azonosítás sikeresen ki lett kapcsolva.");

            _passwordAuthenticationProvider.Verify(x => x.VerifyPassword(It.IsAny<string>(), It.IsAny<string>()), Times.Once);
            _totpProvider.Verify(x => x.VerifyTotp(It.IsAny<byte[]>(), It.IsAny<string>()), Times.Once);
            _userRepository.Verify(x => x.UpdateAsync(It.IsAny<User>()), Times.Once);
        }

        [Fact]
        public async Task DisableTotpAsync_ShouldReturnErrorIfPasswordIsInvalid()
        {
            // Arrange
            var user = new User { TotpEnabled = true, TotpSecret = "test", PasswordHash = "hash" };
            var request = new DisableTOTPRequest("123456", "invalid");

            // Act
            var result = await _service.DisableTotpAsync(user, request);

            // Assert
            result.Should().NotBeNull();
            result.Status.Should().Be("ERR");
            
            var message = (string)result.Message;
            message.Should().Be("Érvénytelen jelszó.");

            _passwordAuthenticationProvider.Verify(x => x.VerifyPassword(It.IsAny<string>(), It.IsAny<string>()), Times.Once);
            _totpProvider.Verify(x => x.VerifyTotp(It.IsAny<byte[]>(), It.IsAny<string>()), Times.Never);
            _userRepository.Verify(x => x.UpdateAsync(It.IsAny<User>()), Times.Never);
        }

        [Fact]
        public async Task DisableTotpAsync_ShouldReturnErrorIfTotpIsNotEnabled()
        {
            // Arrange
            var user = new User { TotpEnabled = false };
            var request = new DisableTOTPRequest("123456", "password");

            // Act
            var result = await _service.DisableTotpAsync(user, request);

            // Assert
            result.Should().NotBeNull();
            result.Status.Should().Be("ERR");

            var message = (string)result.Message;
            message.Should().Be("A kétlépcsős azonosítás nincs engedélyezve.");

            _passwordAuthenticationProvider.Verify(x => x.VerifyPassword(It.IsAny<string>(), It.IsAny<string>()), Times.Never);
            _totpProvider.Verify(x => x.VerifyTotp(It.IsAny<byte[]>(), It.IsAny<string>()), Times.Never);
            _userRepository.Verify(x => x.UpdateAsync(It.IsAny<User>()), Times.Never);
        }

        [Fact]
        public async Task DisableTotpAsync_ShouldReturnErrorIfTotpIsInvalid()
        {
            // Arrange
            var user = new User { TotpEnabled = true, TotpSecret = "test", PasswordHash = "hash" };
            var request = new DisableTOTPRequest("654321", "password");

            // Act
            var result = await _service.DisableTotpAsync(user, request);

            // Assert
            result.Should().NotBeNull();
            result.Status.Should().Be("ERR");

            var message = (string)result.Message;
            message.Should().Be("Érvénytelen kód.");

            _passwordAuthenticationProvider.Verify(x => x.VerifyPassword(It.IsAny<string>(), It.IsAny<string>()), Times.Once);
            _totpProvider.Verify(x => x.VerifyTotp(It.IsAny<byte[]>(), It.IsAny<string>()), Times.Once);
            _userRepository.Verify(x => x.UpdateAsync(It.IsAny<User>()), Times.Never);
        }

        [Fact]
        public async Task GenerateTotpTokenAsync_ShouldGenerateTotpToken()
        {
            // Arrange
            var user = new User { TotpEnabled = false };

            // Act
            var result = await _service.GenerateTotpTokenAsync(user);

            // Assert
            result.Should().NotBeNull();
            result.Status.Should().Be("OK");

            var message = (string)result.Message;
            message.Should().NotBeNull();
            message.Should().HaveLength(32);

            _userRepository.Verify(x => x.UpdateAsync(It.IsAny<User>()), Times.Once);
        }

        [Fact]
        public async Task GenerateTotpTokenAsync_ShouldReturnErrorIfTotpIsAlreadyEnabled()
        {
            // Arrange
            var user = new User { TotpEnabled = true };

            // Act
            var result = await _service.GenerateTotpTokenAsync(user);

            // Assert
            result.Should().NotBeNull();
            result.Status.Should().Be("ERR");

            var message = (string)result.Message;
            message.Should().NotBeNull();
            message.Should().Be("A kétlépcsős azonosítás már engedélyezve van.");

            _userRepository.Verify(x => x.UpdateAsync(It.IsAny<User>()), Times.Never);
        }

        [Fact]
        public async Task GetCasesAsync_ShouldReturnCases()
        {
            // Act
            var result = await _service.GetCasesAsync();

            // Assert
            result.Should().NotBeNull();
            result.Status.Should().Be("OK");

            var message = (List<CaseResponse>)result.Message;
            message.Should().NotBeNull();
            message.Should().HaveCount(2);

            _itemRepository.Verify(x => x.GetAllCasesAsync(), Times.Once);
            _caseItemRepository.Verify(x => x.GetCaseItemsAsync(It.IsAny<int>()), Times.Exactly(2));
        }

        [Fact]
        public async Task GetGiveawaysAsync_ShouldReturnGiveaways()
        {
            // Arrange
            var user = new User { UserId = 1 };

            // Act
            var result = await _service.GetGiveawaysAsync(user);

            // Assert
            result.Should().NotBeNull();
            result.Status.Should().Be("OK");

            var message = (List<CurrentGiveawayResponse>)result.Message;
            message.Should().NotBeNull();
            message.Should().HaveCount(2);

            _giveawayRepository.Verify(x => x.GetCurrentGiveawaysAsync(), Times.Once);
        }

        [Fact]
        public async Task GetInventoryAsync_ShouldReturnInventory()
        {
            // Arrange
            var user = new User { UserId = 1 };

            // Act
            var result = await _service.GetInventoryAsync(user);

            // Assert
            result.Should().NotBeNull();
            result.Status.Should().Be("OK");

            var message = (List<InventoryItemResponse>)result.Message;
            message.Should().NotBeNull();
            message.Should().HaveCount(5);

            _userInventoryRepository.Verify(x => x.GetUserInventoryAsync(It.IsAny<int>()), Times.Once);
        }

        [Fact]
        public async Task GetPastGiveawaysAsync_ShouldReturnPastGiveaways()
        {
            // Act
            var result = await _service.GetPastGiveawaysAsync();

            // Assert
            result.Should().NotBeNull();
            result.Status.Should().Be("OK");

            var message = (List<PastGiveawayResponse>)result.Message;
            message.Should().NotBeNull();
            message.Should().HaveCount(1);

            _giveawayRepository.Verify(x => x.GetPastGiveawaysAsync(), Times.Once);
        }

        [Fact]
        public async Task GetProfileAsync_ShouldReturnProfile()
        {
            // Arrange
            var user = new User {
                UserId = 1,
                Balance = 100,
                Email = "test@example.com",
                IsAdmin = false,
                Username = "user1",
                LoginStreak = 5,
                LastClaimDate = _dateTimeProvider.Object.Now.AddDays(-1),
                TotpEnabled = true,
                WebauthnEnabled = false
            };

            // Act
            var result = await _service.GetProfileAsync(user);

            // Assert
            result.Should().NotBeNull();
            result.Status.Should().Be("OK");

            var message = (UserResponse)result.Message;
            message.Should().NotBeNull();
            message.Should().BeEquivalentTo(user.ToDto(null!));
        }

        [Fact]
        public async Task GetUpgradeItemsAsync_ShouldReturnUpgradeItems()
        {
            // Arrange
            var user = new User { UserId = 1 };
            var request = new ItemUpgradeListRequest([1, 2], 2);

            // Act
            var result = await _service.GetUpgradeItemsAsync(user, request);

            // Assert
            result.Should().NotBeNull();
            result.Status.Should().Be("OK");

            var message = (List<UpgradeItemInfo>)result.Message;
            message.Should().NotBeNull();
            message.Should().HaveCount(1);

            _userInventoryRepository.Verify(x => x.GetUserInventoryAsync(It.IsAny<int>()), Times.Once);
            _itemRepository.Verify(x => x.GetUpgradeItemsAsync(It.IsAny<decimal>()), Times.Once);
        }

        [Fact]
        public async Task GetUpgradeItemsAsync_ShouldReturnErrorIfItemNotInInventory()
        {
            // Arrange
            var user = new User { UserId = 1 };
            var request = new ItemUpgradeListRequest([6], 2);

            // Act
            var result = await _service.GetUpgradeItemsAsync(user, request);

            // Assert
            result.Should().NotBeNull();
            result.Status.Should().Be("ERR");

            var message = (string)result.Message;
            message.Should().NotBeNull();
            message.Should().Be("A megadott tárgy nem található a leltárban.");

            _userInventoryRepository.Verify(x => x.GetUserInventoryAsync(It.IsAny<int>()), Times.Once);
            _itemRepository.Verify(x => x.GetUpgradeItemsAsync(It.IsAny<decimal>()), Times.Never);
        }

        [Fact]
        public async Task GetUpgradeItemsAsync_ShouldReturnErrorIfNoUpgradePathsFound()
        {
            // Arrange
            var user = new User { UserId = 1, Username = "user1" };
            var request = new ItemUpgradeListRequest([1, 2, 5], 10);

            // Act
            var result = await _service.GetUpgradeItemsAsync(user, request);

            // Assert
            result.Should().NotBeNull();
            result.Status.Should().Be("ERR");

            var message = (string)result.Message;
            message.Should().NotBeNull();
            message.Should().Be("A tárgy nem fejleszthető tovább.");

            _userInventoryRepository.Verify(x => x.GetUserInventoryAsync(It.IsAny<int>()), Times.Once);
            _itemRepository.Verify(x => x.GetUpgradeItemsAsync(It.IsAny<decimal>()), Times.Once);
        }

        [Fact]
        public async Task GetUserAsync_ShouldReturnUser()
        {
            // Act
            var result = await _service.GetUserAsync("user1");

            // Assert
            result.Should().NotBeNull();
            result.Status.Should().Be("OK");

            var message = (User)result.Message;
            message.Should().NotBeNull();

            _userRepository.Verify(x => x.GetByUsernameAsync(It.IsAny<string>()), Times.Once);
        }

        [Fact]
        public async Task GetUserAsync_ShouldReturnErrorIfUserNotFound()
        {
            // Act
            var result = await _service.GetUserAsync("invalid");

            // Assert
            result.Should().NotBeNull();
            result.Status.Should().Be("ERR");

            var message = (string)result.Message;
            message.Should().NotBeNull();
            message.Should().Be("A felhasználó nem található.");

            _userRepository.Verify(x => x.GetByUsernameAsync(It.IsAny<string>()), Times.Once);
        }

        [Fact]
        public async Task GetUsersAsync_ShouldReturnUsers()
        {
            // Act
            var result = await _service.GetUsersAsync();

            // Assert
            result.Should().NotBeNull();
            result.Status.Should().Be("OK");

            var message = (List<UserResponse>)result.Message;
            message.Should().NotBeNull();
            message.Should().HaveCount(2);

            _userRepository.Verify(x => x.GetAllAsync(), Times.Once);
            _userInventoryRepository.Verify(x => x.GetUserInventoryAsync(It.IsAny<int>()), Times.Exactly(2));
        }

        [Fact]
        public async Task JoinGiveawayAsync_ShouldJoinGiveaway()
        {
            // Arrange
            var user = new User { UserId = 1 };

            // Act
            var result = await _service.JoinGiveawayAsync(user, 2);

            // Assert
            result.Should().NotBeNull();
            result.Status.Should().Be("OK");

            var message = (string)result.Message;
            message.Should().Be("Sikeresen csatlakoztál a nyereményjátékhoz.");

            _giveawayRepository.Verify(x => x.GetByIdAsync(It.IsAny<int>()), Times.Once);
            _giveawayRepository.Verify(x => x.UpdateAsync(It.IsAny<Giveaway>()), Times.Once);
        }

        [Fact]
        public async Task JoinGiveawayAsync_ShouldReturnErrorIfAlreadyJoined()
        {
            // Arrange
            var user = new User { UserId = 1 };

            // Act
            var result = await _service.JoinGiveawayAsync(user, 1);

            // Assert
            result.Should().NotBeNull();
            result.Status.Should().Be("ERR");

            var message = (string)result.Message;
            message.Should().Be("Már csatlakoztál a nyereményjátékhoz.");

            _giveawayRepository.Verify(x => x.GetByIdAsync(It.IsAny<int>()), Times.Once);
            _giveawayRepository.Verify(x => x.UpdateAsync(It.IsAny<Giveaway>()), Times.Never);
        }

        [Fact]
        public async Task JoinGiveawayAsync_ShouldReturnErrorIfGiveawayNotFound()
        {
            // Arrange
            var user = new User { UserId = 1 };

            // Act
            var result = await _service.JoinGiveawayAsync(user, 100);

            // Assert
            result.Should().NotBeNull();
            result.Status.Should().Be("ERR");

            var message = (string)result.Message;
            message.Should().Be("A megadott nyereményjáték nem található.");

            _giveawayRepository.Verify(x => x.GetByIdAsync(It.IsAny<int>()), Times.Once);
            _giveawayRepository.Verify(x => x.UpdateAsync(It.IsAny<Giveaway>()), Times.Never);
        }

        [Fact]
        public async Task JoinGiveawayAsync_ShouldReturnErrorIfGiveawayIsClosed()
        {
            // Arrange
            var user = new User { UserId = 1 };

            // Act
            var result = await _service.JoinGiveawayAsync(user, 3);

            // Assert
            result.Should().NotBeNull();
            result.Status.Should().Be("ERR");

            var message = (string)result.Message;
            message.Should().Be("A nyereményjáték már lezárult.");

            _giveawayRepository.Verify(x => x.GetByIdAsync(It.IsAny<int>()), Times.Once);
            _giveawayRepository.Verify(x => x.UpdateAsync(It.IsAny<Giveaway>()), Times.Never);
        }
    }
}
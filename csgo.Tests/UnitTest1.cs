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
            _totpProvider = MockRepositories.GetMockTotpProvider();

            _service = new CSGOBackendService(_caseItemRepository.Object, _giveawayRepository.Object, _itemRepository.Object, _userInventoryRepository.Object, _userRepository.Object, _dateTimeProvider.Object, _totpProvider.Object, _mockFido2.Object);
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
            var result = await _service.DeleteCaseItemAsync(6, 1);

            // Assert
            result.Should().NotBeNull();
            result.Status.Should().Be("OK");

            var message = (CaseResponse)result.Message;
            message.Should().NotBeNull();
            message.Items.Should().HaveCount(1);

            _caseItemRepository.Verify(x => x.DeleteAsync(It.IsAny<CaseItem>()), Times.Once);
            _caseItemRepository.Verify(x => x.GetCaseItemsAsync(It.IsAny<int>()), Times.Once);
        }
    }
}
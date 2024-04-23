using csgo.Data;
using csgo.Models;
using csgo.Services;
using Moq;

namespace csgo.Tests
{
    public static class MockRepositories
    {
        public static Mock<ICaseItemRepository> GetMockCaseItemRepository()
        {
            var items = new List<Item>
            {
                new() { ItemId = 1, ItemName = "Item 1" },
                new() { ItemId = 2, ItemName = "Item 2" },
                new() { ItemId = 3, ItemName = "Item 3" },
                new() { ItemId = 5, ItemName = "Item 2" }
            };

            var cases = new List<Item>
            {
                new() { ItemId = 6, ItemName = "Case 1" },
                new() { ItemId = 2, ItemName = "Case 2" }
            };

            var caseItems = new List<CaseItem>
            {
                new()
                {
                    CaseId = 6,
                    ItemId = 1,
                    Case = cases.First(c => c.ItemId == 6),
                    Item = items.First(i => i.ItemId == 1)
                },
                new()
                {
                    CaseId = 6,
                    ItemId = 5,
                    Case = cases.First(c => c.ItemId == 6),
                    Item = items.First(i => i.ItemId == 5)
                },
                new()
                {
                    CaseId = 2,
                    ItemId = 5,
                    Case = cases.First(c => c.ItemId == 2),
                    Item = items.First(i => i.ItemId == 5)
                }
            };

            var mockRepo = new Mock<ICaseItemRepository>();

            mockRepo
                .Setup(r => r.AddAsync(It.IsAny<CaseItem>()))
                .Callback<CaseItem>(caseItem =>
                {
                    var @case = cases.FirstOrDefault(c => c.ItemId == caseItem.CaseId);
                    var item = items.FirstOrDefault(i => i.ItemId == caseItem.ItemId);

                    if (@case != null && item != null)
                    {
                        caseItem.Case = @case;
                        caseItem.Item = item;
                        caseItems.Add(caseItem);
                    }
                })
                .Returns(Task.CompletedTask);

            mockRepo
                .Setup(r => r.DeleteAsync(It.IsAny<CaseItem>()))
                .Callback((CaseItem caseItem) => caseItems.Remove(caseItem))
                .Returns(Task.CompletedTask);

            mockRepo
                .Setup(r => r.GetCaseItemsAsync(It.IsAny<int>()))
                .ReturnsAsync((int caseId) => caseItems.Where(ci => ci.CaseId == caseId).ToList());

            mockRepo
                .Setup(r => r.GetCaseItemByIdAsync(It.IsAny<int>(), It.IsAny<int>()))
                .ReturnsAsync(
                    (int caseId, int itemId) =>
                        caseItems.FirstOrDefault(ci => ci.CaseId == caseId && ci.ItemId == itemId)
                );

            return mockRepo;
        }

        public static Mock<IGiveawayRepository> GetMockGiveawayRepository()
        {
            var users = new List<User>
            {
                new() { UserId = 1, Username = "user1" },
                new() { UserId = 2, Username = "user2" }
            };

            var giveaways = new List<Giveaway>
            {
                new()
                {
                    GiveawayId = 1,
                    GiveawayDate = new DateTime(2024, 3, 20),
                    ItemId = 1,
                    WinnerUserId = null,
                    Users = users
                },
                new()
                {
                    GiveawayId = 2,
                    GiveawayDate = new DateTime(2024, 3, 21),
                    ItemId = 5,
                    WinnerUserId = null
                },
                new()
                {
                    GiveawayId = 3,
                    GiveawayDate = new DateTime(2024, 3, 18),
                    ItemId = 5,
                    WinnerUserId = 1,
                    WinnerUser = new User { UserId = 1, Username = "user1" }
                }
            };

            var mockRepo = new Mock<IGiveawayRepository>();

            mockRepo
                .Setup(r => r.GetByIdAsync(It.IsAny<int>()))
                .ReturnsAsync((int id) => giveaways.FirstOrDefault(g => g.GiveawayId == id));

            mockRepo
                .Setup(r => r.AddAsync(It.IsAny<Giveaway>()))
                .Callback<Giveaway>(giveaway =>
                {
                    giveaway.GiveawayId = giveaways.Last().GiveawayId + 1;
                    giveaways.Add(giveaway);
                })
                .Returns(Task.CompletedTask);

            mockRepo
                .Setup(r => r.UpdateAsync(It.IsAny<Giveaway>()))
                .Callback<Giveaway>(giveaway =>
                {
                    var existingGiveaway = giveaways.FirstOrDefault(g =>
                        g.GiveawayId == giveaway.GiveawayId
                    );
                    if (existingGiveaway != null)
                    {
                        giveaways.Remove(existingGiveaway);
                        giveaways.Add(giveaway);
                    }
                })
                .Returns(Task.CompletedTask);

            mockRepo
                .Setup(r => r.DeleteAsync(It.IsAny<Giveaway>()))
                .Callback<Giveaway>(giveaway => giveaways.Remove(giveaway))
                .Returns(Task.CompletedTask);

            mockRepo
                .Setup(r => r.GetParticipantsAsync(It.IsAny<Giveaway>()))
                .Returns((Giveaway giveaway) => Task.FromResult(giveaway.Users.ToList()));

            mockRepo
                .Setup(r => r.GetCurrentGiveawaysAsync())
                .ReturnsAsync(
                    () =>
                        giveaways
                            .Where(g => g.GiveawayDate >= DateTime.Now && g.WinnerUserId == null)
                            .ToList()
                );

            mockRepo
                .Setup(r => r.GetPastGiveawaysAsync())
                .ReturnsAsync(
                    () =>
                        giveaways
                            .Where(g => g.GiveawayDate < DateTime.Now && g.WinnerUserId != null)
                            .ToList()
                );

            return mockRepo;
        }

        public static Mock<IItemRepository> GetMockItemRepository()
        {
            var items = new List<Item>
            {
                new()
                {
                    ItemId = 1,
                    ItemName = "Item 1",
                    ItemType = ItemType.Item,
                    ItemValue = 10.0m
                },
                new()
                {
                    ItemId = 5,
                    ItemName = "Item 2",
                    ItemType = ItemType.Item,
                    ItemValue = 15.0m
                },
                new()
                {
                    ItemId = 2,
                    ItemName = "Case 1",
                    ItemType = ItemType.Case,
                    ItemValue = 5.0m
                },
                new()
                {
                    ItemId = 6,
                    ItemName = "Case 2",
                    ItemType = ItemType.Case,
                    ItemValue = 8.0m
                }
            };

            var mockRepo = new Mock<IItemRepository>();

            mockRepo
                .Setup(r => r.GetItemByIdAsync(It.IsAny<int>()))
                .ReturnsAsync(
                    (int id) =>
                        items.FirstOrDefault(i => i.ItemId == id && i.ItemType == ItemType.Item)
                );

            mockRepo
                .Setup(r => r.GetCaseByIdAsync(It.IsAny<int>()))
                .ReturnsAsync(
                    (int id) =>
                        items.FirstOrDefault(i => i.ItemId == id && i.ItemType == ItemType.Case)
                );

            mockRepo
                .Setup(r => r.GetUpgradeItemsAsync(It.IsAny<decimal>()))
                .ReturnsAsync(
                    (decimal value) =>
                        items
                            .Where(i => i.ItemType == ItemType.Item && i.ItemValue >= value)
                            .ToList()
                );

            mockRepo
                .Setup(r => r.AddAsync(It.IsAny<Item>()))
                .Callback((Item item) => {
                    item.ItemId = items.Last().ItemId + 1;
                    items.Add(item);
                })
                .Returns(Task.CompletedTask);

            mockRepo
                .Setup(r => r.UpdateAsync(It.IsAny<Item>()))
                .Callback(
                    (Item item) =>
                    {
                        var existingItem = items.FirstOrDefault(i => i.ItemId == item.ItemId);
                        if (existingItem != null)
                        {
                            items.Remove(existingItem);
                            items.Add(item);
                        }
                    }
                )
                .Returns(Task.CompletedTask);

            mockRepo
                .Setup(r => r.DeleteAsync(It.IsAny<Item>()))
                .Callback((Item item) => items.Remove(item))
                .Returns(Task.CompletedTask);

            mockRepo
                .Setup(r => r.GetAllItemsAsync())
                .ReturnsAsync(() => items.Where(i => i.ItemType == ItemType.Item).ToList());

            mockRepo
                .Setup(r => r.GetAllCasesAsync())
                .ReturnsAsync(() => items.Where(i => i.ItemType == ItemType.Case).ToList());

            return mockRepo;
        }

        public static Mock<IUserInventoryRepository> GetMockUserInventoryRepository()
        {
            var mockRepo = new Mock<IUserInventoryRepository>();

            var users = new List<User>
            {
                new()
                {
                    UserId = 1,
                    Username = "user1",
                    Email = "user1@example.com",
                }
            };

            var items = new List<Item>
            {
                new()
                {
                    ItemId = 1,
                    ItemAssetUrl = "https://example.com/item1.jpg",
                    ItemName = "Item 1",
                    ItemType = ItemType.Item,
                    ItemValue = 10.0m,
                    ItemDescription = "Item 1 description",
                    ItemRarity = ItemRarity.INDUSTRIAL_GRADE,
                    ItemSkinName = "Item 1 skin",
                },
                new()
                {
                    ItemId = 2,
                    ItemAssetUrl = "https://example.com/item2.jpg",
                    ItemName = "Case 1",
                    ItemType = ItemType.Case,
                    ItemValue = 20.0m,
                    ItemDescription = "Case 1 description",
                    ItemRarity = ItemRarity.EXTRAORDINARY,
                    ItemSkinName = "Case 1 skin",
                }
            };

            var userInventoryList = new List<Userinventory>
            {
                new()
                {
                    InventoryId = 1,
                    UserId = 1,
                    ItemId = 1,
                    Item = items.First(item => item.ItemId == 1),
                    User = users.First(user => user.UserId == 1)
                },
                new()
                {
                    InventoryId = 2,
                    UserId = 1,
                    ItemId = 2,
                    Item = items.First(item => item.ItemId == 2),
                    User = users.First(user => user.UserId == 1)
                },
                new()
                {
                    InventoryId = 3,
                    UserId = 1,
                    ItemId = 2,
                    Item = items.First(item => item.ItemId == 2),
                    User = users.First(user => user.UserId == 1)
                }
            };

            mockRepo
                .Setup(r => r.GetById(It.IsAny<int>()))
                .ReturnsAsync(
                    (int id) =>
                    {
                        return userInventoryList.FirstOrDefault(x => x.InventoryId == id);
                    }
                );

            mockRepo
                .Setup(r => r.AddAsync(It.IsAny<Userinventory>()))
                .Callback<Userinventory>(userInventory =>
                {
                    var user = users.FirstOrDefault(u => u.UserId == userInventory.UserId);
                    var item = items.FirstOrDefault(i => i.ItemId == userInventory.ItemId);

                    if (user != null && item != null)
                    {
                        userInventory.InventoryId = userInventoryList.Last().InventoryId + 1;
                        userInventory.User = user;
                        userInventory.Item = item;
                        userInventoryList.Add(userInventory);
                    }
                })
                .Returns(Task.CompletedTask);

            mockRepo
                .Setup(r => r.DeleteAsync(It.IsAny<Userinventory>()))
                .Callback((Userinventory inventory) => userInventoryList.Remove(inventory))
                .Returns(Task.CompletedTask);

            mockRepo
                .Setup(r => r.GetUserInventoryAsync(It.IsAny<int>()))
                .ReturnsAsync(
                    (int userId) =>
                    {
                        return userInventoryList.Where(x => x.UserId == userId).ToList();
                    }
                );

            mockRepo
                .Setup(r => r.GetInventoryItemsByItemIdAsync(It.IsAny<int>()))
                .ReturnsAsync(
                    (int itemId) =>
                    {
                        return userInventoryList.Where(x => x.ItemId == itemId).ToList();
                    }
                );

            return mockRepo;
        }

        public static Mock<IUserRepository> GetMockUserRepository()
        {
            var mockRepo = new Mock<IUserRepository>();

            var user1 = new User
            {
                UserId = 1,
                Username = "user1",
                Email = "user1@example.com"
            };

            var user2 = new User
            {
                UserId = 2,
                Username = "user2",
                Email = "user2@example.com"
            };

            var userList = new List<User> { user1, user2 };

            mockRepo
                .Setup(r => r.GetByUsernameAsync(It.IsAny<string>()))
                .ReturnsAsync(
                    (string username) =>
                    {
                        return userList.FirstOrDefault(x => x.Username == username);
                    }
                );

            mockRepo
                .Setup(r => r.GetByIdAsync(It.IsAny<int>()))
                .ReturnsAsync(
                    (int userId) =>
                    {
                        return userList.FirstOrDefault(x => x.UserId == userId);
                    }
                );

            mockRepo
                .Setup(r => r.CredentialIdExistsAsync(It.IsAny<string>()))
                .ReturnsAsync(
                    (string credentialId) =>
                    {
                        return userList.Any(x => x.WebauthnCredentialId == credentialId);
                    }
                );

            mockRepo
                .Setup(r => r.UsernameExistsAsync(It.IsAny<string>(), It.IsAny<int?>()))
                .ReturnsAsync(
                    (string username, int? userId) =>
                    {
                        return userList.Any(x =>
                            x.Username == username && (!userId.HasValue || x.UserId != userId)
                        );
                    }
                );

            mockRepo
                .Setup(r => r.EmailExistsAsync(It.IsAny<string>(), It.IsAny<int?>()))
                .ReturnsAsync(
                    (string email, int? userId) =>
                    {
                        return userList.Any(x =>
                            x.Email == email && (!userId.HasValue || x.UserId != userId)
                        );
                    }
                );

            mockRepo
                .Setup(r => r.AddAsync(It.IsAny<User>()))
                .Callback(
                    (User user) =>
                    {
                        user.UserId = userList.Last().UserId + 1;
                        userList.Add(user);
                    }
                )
                .Returns(Task.CompletedTask);

            mockRepo
                .Setup(r => r.UpdateAsync(It.IsAny<User>()))
                .Callback(
                    (User user) =>
                    {
                        var existingUser = userList.FirstOrDefault(x => x.UserId == user.UserId);
                        if (existingUser != null)
                        {
                            userList.Remove(existingUser);
                            userList.Add(user);
                        }
                    }
                )
                .Returns(Task.CompletedTask);

            mockRepo.Setup(r => r.GetAllAsync()).ReturnsAsync(userList);

            return mockRepo;
        }

        public static Mock<ITotpProvider> GetMockTotpProvider()
        {
            var mockRepo = new Mock<ITotpProvider>();
            mockRepo
                .Setup(r => r.VerifyTotp(It.IsAny<byte[]>(), It.IsAny<string>()))
                .Returns(
                    (byte[] _, string code) =>
                    {
                        return code == "123456";
                    }
                );

            return mockRepo;
        }

        public static Mock<IDateTimeProvider> GetMockDateTimeProvider()
        {
            var mockRepo = new Mock<IDateTimeProvider>();
            mockRepo.Setup(r => r.Now).Returns(new DateTime(2024, 3, 19));
            return mockRepo;
        }
    }
}

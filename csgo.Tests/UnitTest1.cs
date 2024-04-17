using static csgo.Dtos;
using csgo.Models;
using csgo.Services;
using Fido2NetLib;
using FluentAssertions;
using Moq;
using Moq.EntityFrameworkCore;

namespace csgo.Tests
{
    public class CSGOBackendServiceTests
    {
        private readonly Mock<CsgoContext> _mockContext;
        private readonly Mock<IFido2> _mockFido2;
        private readonly CSGOBackendService _service;

        public CSGOBackendServiceTests()
        {
            _mockContext = new Mock<CsgoContext>();
            _mockFido2 = new Mock<IFido2>();
            _service = new CSGOBackendService(_mockContext.Object, _mockFido2.Object);
        }

        [Fact]
        public async Task AddCaseAsync_ShouldAddCase()
        {
            // Arrange
            _mockContext.Setup(x => x.Items).ReturnsDbSet([]);
            var newCase = new CaseRecord("Test Case", (decimal)123.45, "https://test.com");

            // Act
            var result = await _service.AddCaseAsync(newCase);

            // Assert
            result.Should().NotBeNull();
            result.Status.Should().Be("OK");

            var message = (CaseResponse)result.Message!;
            message.Should().NotBeNull();
            message.ItemName.Should().Be(newCase.Name);
            message.ItemValue.Should().Be(newCase.Value);
            message.ItemAssetUrl.Should().Be(newCase.AssetUrl);
            message.Items.Should().BeEmpty();

            _mockContext.Verify(x => x.Items.AddAsync(It.IsAny<Item>(), default), Times.Once());
            _mockContext.Verify(x => x.SaveChangesAsync(default), Times.Once);
        }
    }
}
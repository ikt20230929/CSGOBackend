using AutoMapper;
using csgo.Models;

namespace csgo
{
    public class MappingProfile : Profile
    {
        public MappingProfile(CsgoContext context)
        {
            CreateMap<Skin, Dtos.SkinResponse>();
            CreateMap<Item, Dtos.ItemResponse>();
            CreateMap<Item, Dtos.CaseResponse>()
                .ForMember(dest => dest.Items,
                    opt => opt.MapFrom(src =>
                        context.CaseItems.Where(ci => ci.CaseId == src.ItemId).Select(ci => ci.Item)));
            CreateMap<User, Dtos.UserResponse>();

        }
    }
}
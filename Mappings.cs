using AutoMapper;
using csgo.Models;

namespace csgo
{
    public class MappingProfile : Profile
    {
        public MappingProfile()
        {
            CreateMap<Skin, Dtos.SkinResponse>();
            CreateMap<Item, Dtos.ItemResponse>();
            CreateMap<Case, Dtos.CaseResponse>();
            CreateMap<User, Dtos.UserResponse>();

        }
    }
}
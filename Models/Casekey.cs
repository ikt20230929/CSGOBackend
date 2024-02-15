namespace csgo.Models
{
    public class CaseKey
    {
        public int CaseId { get; set; }
        public int CaseKeyId { get; set; }

        public Item Case { get; set; } // Represents the case
        public Item Key { get; set; } // Represents the case key
    }
}

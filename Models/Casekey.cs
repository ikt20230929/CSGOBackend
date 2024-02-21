namespace csgo.Models
{
    /// <summary>
    /// Egy ládához tartozó kulcs
    /// </summary>
    public class CaseKey
    {
        /// <summary>
        /// A láda azonosítója
        /// </summary>
        public int CaseId { get; set; }

        /// <summary>
        /// A ládához tartózó kulcs azonosítója
        /// </summary>
        public int CaseKeyId { get; set; }

        /// <summary>
        /// A láda
        /// </summary>
        public Item Case { get; set; } = null!;

        /// <summary>
        /// A ládához tartózó kulcs
        /// </summary>
        public Item Key { get; set; } = null!;
    }
}

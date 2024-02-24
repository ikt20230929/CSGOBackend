namespace csgo.Models
{

    /// <summary>
    /// Tárgy ritkaság
    /// </summary>
    public enum ItemRarity
    {
        /// <summary>
        /// Fogyasztói minőségű
        /// </summary>
        CONSUMER_GRADE = 1,
        /// <summary>
        /// Ipari minőségű
        /// </summary>
        INDUSTRIAL_GRADE = 2,
        /// <summary>
        /// Katonai minőségű
        /// </summary>
        MIL_SPEC = 3,
        /// <summary>
        /// Korlátozott
        /// </summary>
        RESTRICTED = 4,
        /// <summary>
        /// Osztályozott
        /// </summary>
        CLASSIFIED = 5,
        /// <summary>
        /// Titkos
        /// </summary>
        COVERT = 6,
        /// <summary>
        /// Rendkívüli
        /// </summary>
        EXTRAORDINARY = 7
    }
}

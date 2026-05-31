using System;

namespace SysMail
{
    /// <summary>
    /// Перелічення, що класифікує тип переданого повідомлення, 
    /// дозволяючи кінцевому автомату системи правильно його інтерпретувати.
    /// </summary>
    public enum MessageType
    {
        Text,       // Звичайне текстове повідомлення від клієнта до клієнта
        System,     // Системні сповіщення (наприклад, "Користувач 3A2B приєднався")
        Command     // Керуючі директиви (наприклад, запит на розірвання сесії "exit")
    }

    /// <summary>
    /// Об'єкт передачі даних (Data Transfer Object), що представляє структуру
    /// інформаційного пакета прикладного рівня. Серіалізується у формат JSON 
    /// перед шифруванням.
    /// </summary>
    public class MessagePacket
    {
        /// <summary>
        /// Тип поточного повідомлення.
        /// </summary>
        public MessageType Type { get; set; }

        /// <summary>
        /// Точний час створення повідомлення на клієнтському пристрої.
        /// </summary>
        public DateTime Timestamp { get; set; }

        /// <summary>
        /// Ідентифікатор вузла, який згенерував повідомлення (коротка форма GUID).
        /// </summary>
        public string SenderId { get; set; } = string.Empty;

        /// <summary>
        /// Відкритий текст повідомлення або зміст керуючої команди.
        /// </summary>
        public string Payload { get; set; } = string.Empty;

        /// <summary>
        /// Криптографічний лічильник послідовності. Кожен наступний пакет 
        /// збільшує значення на 1. Відіграє ключову роль у захисті від Replay-атак.
        /// </summary>
        public long SequenceNumber { get; set; }

        public MessageType MessageType
        {
            get => default;
            set
            {
            }
        }
    }
}

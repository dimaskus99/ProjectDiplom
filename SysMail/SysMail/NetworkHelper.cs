using System;
using System.Net.Sockets;
using System.Threading.Tasks;

namespace SysMail
{
    /// <summary>
    /// Статичний допоміжний клас для забезпечення надійного асинхронного
    /// прийому та передачі байтових потоків через TCP-з'єднання.
    /// Вирішує проблему фрагментації та "злипання" пакетів на рівні сокетів.
    /// </summary>
    public static class NetworkHelper
    {
        public static SecureTcpServer SecureTcpServer
        {
            get => default;
            set
            {
            }
        }

        public static SecureTcpClient SecureTcpClient
        {
            get => default;
            set
            {
            }
        }
        /// <summary>
        /// Асинхронно відправляє масив байтів через мережевий потік.
        /// Реалізує патерн Length-Prefix: спочатку відправляється 4 байти (довжина), 
        /// а потім безпосередньо дані.
        /// </summary>
        /// <param name="stream">Мережевий потік підключеного клієнта.</param>
        /// <param name="data">Масив зашифрованих байтів для передачі.</param>
        public static async Task SendBytesAsync(NetworkStream stream, byte[] data)
        {
            // Перетворення довжини масиву (int, 32 біти) у 4-байтовий масив
            // Використовується порядок байтів процесора (зазвичай Little-Endian на x86)
            byte[] length = BitConverter.GetBytes(data.Length);

            // Відправка префіксу довжини (рівно 4 байти)
            await stream.WriteAsync(length, 0, 4);

            // Відправка безпосередньо корисного навантаження (Payload)
            await stream.WriteAsync(data, 0, data.Length);
        }

        /// <summary>
        /// Асинхронно приймає масив байтів, орієнтуючись на отриманий префікс довжини.
        /// Гарантує зчитування повного логічного пакету.
        /// </summary>
        /// <param name="stream">Мережевий потік підключеного клієнта.</param>
        /// <returns>Повністю зчитаний масив байтів (Payload).</returns>
        public static async Task<byte[]> ReceiveBytesAsync(NetworkStream stream)
        {
            // Буфер для зчитування префіксу довжини
            byte[] lengthBytes = new byte[4];

            // Зчитування рівно 4 байтів для отримання довжини наступного пакета
            await ReadExactAsync(stream, lengthBytes, 4);
            int length = BitConverter.ToInt32(lengthBytes, 0);

            // Виділення оперативної пам'яті під пакет вирахуваного розміру
            byte[] data = new byte[length];

            // Зчитування самого пакету даних з гарантією повноти
            await ReadExactAsync(stream, data, length);
            return data;
        }

        /// <summary>
        /// Низькорівневий допоміжний метод, що утримує потік у циклі очікування, 
        /// гарантуючи зчитування точної кількості байтів. 
        /// Запобігає пошкодженню даних при частковому надходженні TCP-сегментів.
        /// </summary>
        public static async Task ReadExactAsync(NetworkStream stream, byte[] buffer, int length)
        {
            int totalRead = 0;

            // Цикл виконується, доки сумарна кількість зчитаних байтів 
            // не досягне необхідної довжини пакета
            while (totalRead < length)
            {
                // Зчитування залишкової кількості байтів: (length - totalRead)
                int bytesRead = await stream.ReadAsync(buffer, totalRead, length - totalRead);

                // Якщо метод ReadAsync повертає 0, це є системним індикатором того, 
                // що віддалений вузол ініціював процедуру коректного закриття з'єднання (FIN-пакет)
                if (bytesRead == 0)
                    throw new Exception("З'єднання закрито.");

                // Акумуляція кількості зчитаних байтів
                totalRead += bytesRead;
            }
        }
    }
}

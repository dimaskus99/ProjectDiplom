using System;
using System.Text;
using System.Threading.Tasks;

namespace SysMail
{
    /// <summary>
    /// Головна точка входу в програму. Використовує асинхронний Main 
    /// для підтримки Task-based Asynchronous Pattern (TAP) на рівні ініціалізації.
    /// </summary>
    class Program
    {
        public SecureTcpServer SecureTcpServer
        {
            get => default;
            set
            {
            }
        }

        public SecureTcpClient SecureTcpClient
        {
            get => default;
            set
            {
            }
        }

        static async Task Main()
        {
            // Налаштування кодування UTF-8 для повної системної підтримки 
            // введення та виведення української мови (кирилиці) і спецсимволів емодзі.
            Console.OutputEncoding = Encoding.UTF8;
            Console.InputEncoding = Encoding.UTF8;

            Console.WriteLine("====================================");
            Console.WriteLine("  SECURE REMOTE COMMUNICATION");
            Console.WriteLine("====================================");
            Console.WriteLine("1 - Запустити сервер");
            Console.WriteLine("2 - Запустити клієнт");
            Console.Write("\nВаш вибір: ");

            string? choice = Console.ReadLine();

            // Стандартний порт для роботи додатка (в локальній або глобальній мережі)
            int port = 5000;

            // Ініціалізація екземплярів системи залежно від обраного режиму вузла
            if (choice == "1")
            {
                SecureTcpServer server = new SecureTcpServer();
                // Блокуємо виконання Main до завершення роботи сервера
                await server.StartAsync(port);
            }
            else if (choice == "2")
            {
                Console.Write("IP сервера: ");
                string? ip = Console.ReadLine();

                SecureTcpClient client = new SecureTcpClient();
                // Якщо IP не введено, за замовчуванням підключаємося до локального хоста (Loopback)
                await client.StartAsync(ip ?? "127.0.0.1", port);
            }
            else
            {
                Console.WriteLine("Невірний вибір.");
            }

            Console.WriteLine("\nНатисніть будь-яку клавішу...");
            Console.ReadKey();
        }
    }
}
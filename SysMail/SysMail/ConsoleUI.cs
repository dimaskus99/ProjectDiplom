using System;

namespace SysMail
{
    /// <summary>
    /// Статичний клас для забезпечення потокобезпечного (Thread-safe) вводу та виводу
    /// у консоль. Вирішує проблему перекриття (tearing) тексту під час паралельного 
    /// отримання повідомлень з мережі та набору тексту користувачем.
    /// </summary>
    public static class ConsoleUI
    {
        // Буфер для збереження поточних введених символів користувача
        private static string _currentInput = "";

        // Об'єкт синхронізації (м'ютекс) для ізоляції критичних секцій вводу-виводу
        private static readonly object _lock = new object();

        // Прапорець стану, що інформує інші потоки про процес активного введення тексту
        private static bool _isReading = false;

        public static SecureTcpClient SecureTcpClient
        {
            get => default;
            set
            {
            }
        }

        public static SecureTcpServer SecureTcpServer
        {
            get => default;
            set
            {
            }
        }

        internal static Program Program
        {
            get => default;
            set
            {
            }
        }

        /// <summary>
        /// Безпечно виводить повідомлення на екран, зберігаючи поточний контекст набору.
        /// </summary>
        /// <param name="message">Текст для відображення.</param>
        public static void PrintMessage(string message)
        {
            // Встановлення блокування потоку, щоб уникнути конфліктів доступу до консолі
            lock (_lock)
            {
                if (_isReading)
                {
                    // Якщо користувач зараз друкує текст, тимчасово стираємо його поточний рядок,
                    // виводимо нове повідомлення зверху, і повертаємо введений текст назад на новий рядок.
                    ClearCurrentLine();
                    Console.WriteLine(message);
                    Console.Write($"[ВИ]: {_currentInput}");
                }
                else
                {
                    // Якщо користувач нічого не вводить, просто друкуємо повідомлення
                    Console.WriteLine(message);
                }
            }
        }

        /// <summary>
        /// Зчитує рядок тексту, обробляючи кожне натискання клавіші індивідуально
        /// за допомогою перехоплення KeyChar.
        /// </summary>
        /// <returns>Фінальний рядок, введений користувачем до натискання Enter.</returns>
        public static string ReadLine()
        {
            lock (_lock)
            {
                _currentInput = "";
                _isReading = true;
                Console.Write("[ВИ]: ");
            }

            while (true)
            {
                // Перехоплення натиснутої клавіші БЕЗ автоматичного системного виводу на екран
                var keyInfo = Console.ReadKey(intercept: true);

                lock (_lock)
                {
                    if (keyInfo.Key == ConsoleKey.Enter)
                    {
                        // Користувач завершив введення
                        Console.WriteLine();
                        string result = _currentInput;
                        _currentInput = "";
                        _isReading = false;
                        return result;
                    }
                    else if (keyInfo.Key == ConsoleKey.Backspace)
                    {
                        // Програмна обробка стирання символів з буфера та візуально з екрану
                        if (_currentInput.Length > 0)
                        {
                            _currentInput = _currentInput.Substring(0, _currentInput.Length - 1);
                            // Повертаємо курсор назад (\b), друкуємо пробіл (стираємо символ), і знову назад (\b)
                            Console.Write("\b \b");
                        }
                    }
                    else if (!char.IsControl(keyInfo.KeyChar))
                    {
                        // Додавання допустимого (не керуючого) символу у внутрішній буфер
                        _currentInput += keyInfo.KeyChar;
                        Console.Write(keyInfo.KeyChar);
                    }
                }
            }
        }

        /// <summary>
        /// Допоміжний низькорівневий метод для очищення поточного рядка в консолі
        /// перед виводом нового системного повідомлення.
        /// </summary>
        private static void ClearCurrentLine()
        {
            try
            {
                // Збереження поточної координати Y курсора
                int currentLineCursor = Console.CursorTop;

                // Переміщення курсора на початок рядка (X = 0)
                Console.SetCursorPosition(0, currentLineCursor);

                // Заповнення всього рядка пробілами для стирання попереднього тексту
                Console.Write(new string(' ', Console.WindowWidth - 1));

                // Повернення курсора на початок для підготовки до нового виводу
                Console.SetCursorPosition(0, currentLineCursor);
            }
            catch
            {
                // Резервний варіант (Fallback) виконання на випадок перенаправлення 
                // потоків вводу-виводу (pipes) або нестандартних консолей ОС Linux
                Console.Write("\r" + new string(' ', 50) + "\r");
            }
        }
    }
}

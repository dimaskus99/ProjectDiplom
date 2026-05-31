using System;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace SysMail
{
    /// <summary>
    /// Клас клієнтського застосунку. Забезпечує ініціалізацію підключення, 
    /// строгу криптографічну валідацію сервера (X.509) та захищений повнодуплексний зв'язок.
    /// </summary>
    public class SecureTcpClient : CryptoSession
    {
        // Лічильники послідовностей (Sequence Numbers) для синхронізації 
        // пакетів та безпомилкового виявлення спроб Replay-атак з боку мережі.
        private long _outboundSequence = 0;
        private long _inboundSequence = 0;

        public MessagePacket MessagePacket
        {
            get => default;
            set
            {
            }
        }

        /// <summary>
        /// Головний метод старту роботи клієнта.
        /// </summary>
        /// <param name="ip">IP-адреса віддаленого сервера.</param>
        /// <param name="port">Мережевий порт TCP.</param>
        public async Task StartAsync(string ip, int port)
        {
            using TcpClient client = new TcpClient();

            // Асинхронне підключення до сервера (не блокує UI)
            await client.ConnectAsync(ip, port);

            Console.WriteLine($"[КЛІЄНТ] Підключено до {ip}:{port}");

            using NetworkStream stream = client.GetStream();

            // Ініціалізація клієнтського екземпляра криптографічного ядра
            using CryptoSession crypto = new CryptoSession();

            // === ФАЗА 1. ОТРИМАННЯ ТА ВАЛІДАЦІЯ АВТЕНТИФІКАЦІЙНИХ ДАНИХ СЕРВЕРА ===

            byte[] serverCertBytes = await NetworkHelper.ReceiveBytesAsync(stream);
            byte[] serverEcdhPubKey = await NetworkHelper.ReceiveBytesAsync(stream);
            byte[] signature = await NetworkHelper.ReceiveBytesAsync(stream);

            // Реконструкція об'єкта сертифіката з байтового масиву
            using var serverCertificate = new X509Certificate2(serverCertBytes);

            // Видобуток публічного ключа ідентичності сервера (ECDSA)
            using var serverIdentity = serverCertificate.GetECDsaPublicKey();

            if (serverIdentity == null)
            {
                Console.WriteLine("\n[КЛІЄНТ] ❌ ПОМИЛКА: Сертифікат сервера не містить ключа ECDSA!");
                return;
            }

            // ВАЛІДАЦІЯ ЦИФРОВОГО ПІДПИСУ: Перевірка криптографічної довіри.
            // Функція математично гарантує, що переданий ECDH-ключ (для шифрування сесії)
            // дійсно належить власнику X.509 сертифіката, а не був підмінений на маршрутизаторі.
            bool isSignatureValid = serverIdentity.VerifyData(serverEcdhPubKey, signature, HashAlgorithmName.SHA256);

            if (!isSignatureValid)
            {
                // Якщо підпис не співпадає, з'єднання негайно скидається
                Console.WriteLine("\n[КЛІЄНТ] ❌ КРИТИЧНА ПОМИЛКА: Недійсний цифровий підпис сервера!");
                return;
            }
            Console.WriteLine($"[КЛІЄНТ] ✅ Сертифікат сервера ({serverCertificate.Subject}) перевірено.");

            // === ФАЗА 2. ВІДПРАВКА СВОГО ЕФЕМЕРНОГО КЛЮЧА ТА ОБЧИСЛЕННЯ СЕКРЕТУ ===

            byte[] myPublicKey = crypto.GetPublicKey();
            await NetworkHelper.SendBytesAsync(stream, myPublicKey);

            // Запуск алгоритму HKDF для деривації симетричного ключа AES/ChaCha20
            crypto.DeriveSessionKey(serverEcdhPubKey);

            // === ФАЗА 3. УЗГОДЖЕННЯ АЛГОРИТМІВ (Cipher Suite Negotiation) ===

            // Повідомляємо сервер про наявність апаратної підтримки алгоритмів AES-NI
            string supportedSuites = AesGcm.IsSupported ? "AES-GCM,ChaCha20" : "ChaCha20";
            await NetworkHelper.SendBytesAsync(stream, System.Text.Encoding.UTF8.GetBytes(supportedSuites));

            // Отримання фінального рішення від сервера щодо обраного алгоритму
            byte[] selectedSuiteBytes = await NetworkHelper.ReceiveBytesAsync(stream);
            string selectedSuite = System.Text.Encoding.UTF8.GetString(selectedSuiteBytes);

            // Застосування обраного алгоритму в ядрі
            if (selectedSuite == "AES-GCM")
                crypto.SetCipherSuite(CipherSuite.Aes256Gcm);
            else
                crypto.SetCipherSuite(CipherSuite.ChaCha20Poly1305);

            Console.WriteLine($"[КЛІЄНТ] Алгоритм шифрування: {selectedSuite}");
            Console.WriteLine("[КЛІЄНТ] Захищений канал встановлено. Можна писати.");
            Console.WriteLine("------------------------------------------------------------------");

            // Ініціалізація токену скасування для узгодженого та каскадного завершення потоків
            using var cts = new CancellationTokenSource();

            // === ФАЗА 4. БАГАТОПОТОКОВА ОБРОБКА ВВОДУ-ВИВОДУ ===

            // ЗАДАЧА 1: Паралельний потік прийому повідомлень з мережі
            Task receiveTask = Task.Run(async () =>
            {
                while (!cts.Token.IsCancellationRequested)
                {
                    try
                    {
                        // Очікування нового крипто-пакета
                        byte[] encryptedData = await NetworkHelper.ReceiveBytesAsync(stream);
                        string json = crypto.DecryptData(encryptedData);

                        MessagePacket? packet = JsonSerializer.Deserialize<MessagePacket>(json);
                        if (packet == null) continue;

                        // БЕЗПЕКА: Валідація лічильника (Replay Protection)
                        // Кожен пакет має унікальний номер. Дублікати відхиляються.
                        if (packet.SequenceNumber != _inboundSequence)
                        {
                            ConsoleUI.PrintMessage($"\n[КЛІЄНТ] ❌ ВИТІК БЕЗПЕКИ: Виявлено Replay-атаку! Очікувався пакет {_inboundSequence}, отримано {packet.SequenceNumber}.");
                            cts.Cancel();   // Аварійне скасування всіх задач
                            break;
                        }
                        _inboundSequence++; // Інкремент успішно обробленого пакету

                        string timeInfo = packet.Timestamp.ToString("HH:mm:ss");

                        // Маршрутизація відображення залежно від типу повідомлення
                        if (packet.Type == MessageType.System)
                        {
                            ConsoleUI.PrintMessage($"[{timeInfo}] *** {packet.Payload} ***");
                        }
                        else if (packet.Type == MessageType.Text)
                        {
                            ConsoleUI.PrintMessage($"[{timeInfo}] [{packet.SenderId}]: {packet.Payload}");
                        }
                    }
                    catch
                    {
                        // Якщо помилка сталася не через ініціативу самого клієнта (cts.Cancel)
                        if (!cts.Token.IsCancellationRequested)
                        {
                            ConsoleUI.PrintMessage("[КЛІЄНТ] З'єднання з сервером втрачено.");
                            cts.Cancel();
                        }
                        break;
                    }
                }
            }, cts.Token);

            // ЗАДАЧА 2: Паралельний потік обробки введення користувача
            Task sendTask = Task.Run(async () =>
            {
                while (!cts.Token.IsCancellationRequested)
                {
                    try
                    {
                        // Синхронізоване зчитування рядка з консолі з підтримкою UI-блокувань
                        string input = ConsoleUI.ReadLine();

                        // Перевірка, чи не надійшов сигнал зупинки під час очікування вводу
                        if (cts.Token.IsCancellationRequested) break;
                        if (string.IsNullOrWhiteSpace(input)) continue;

                        // ОБРОБКА ІНЖЕНЕРНИХ КОМАНД МОНІТОРИНГУ
                        if (input == "/crypto")
                        {
                            string lastNonceStr = crypto.LastNonce != null ? Convert.ToBase64String(crypto.LastNonce) : "Ще не згенеровано";
                            ConsoleUI.PrintMessage("\n=== 🔒 КРИПТОГРАФІЧНИЙ СТАТУС СЕСІЇ ===");
                            ConsoleUI.PrintMessage($"Автентифікація: X.509 (NIST P-256)");
                            ConsoleUI.PrintMessage($"Шифрування: {crypto.SelectedCipher}");
                            ConsoleUI.PrintMessage($"Поточний вихідний Sequence: {_outboundSequence}");
                            ConsoleUI.PrintMessage($"Останній Nonce (12-byte): {lastNonceStr}");
                            ConsoleUI.PrintMessage("=======================================\n");
                            continue;
                        }

                        // Формування структури інформаційного пакета
                        var packet = new MessagePacket
                        {
                            Timestamp = DateTime.Now,
                            SenderId = "Я",
                            // Постфіксний інкремент вихідної послідовності пакета
                            SequenceNumber = _outboundSequence++
                        };

                        // ОБРОБКА КОМАНДИ ВИХОДУ (Graceful Disconnect)
                        if (input == "/exit")
                        {
                            packet.Type = MessageType.Command;
                            packet.Payload = "exit";

                            string exitJson = JsonSerializer.Serialize(packet);
                            byte[] exitData = crypto.EncryptData(exitJson);
                            await NetworkHelper.SendBytesAsync(stream, exitData);

                            // Ініціація скасування паралельної задачі прийому повідомлень
                            cts.Cancel();
                            break;
                        }

                        // ВІДПРАВКА ЗВИЧАЙНОГО ТЕКСТОВОГО ПОВІДОМЛЕННЯ
                        packet.Type = MessageType.Text;
                        packet.Payload = input;

                        string json = JsonSerializer.Serialize(packet);
                        byte[] encryptedData = crypto.EncryptData(json);
                        await NetworkHelper.SendBytesAsync(stream, encryptedData);
                    }
                    catch
                    {
                        cts.Cancel();
                        break;
                    }
                }
            }, cts.Token);

            // Асинхронне очікування завершення будь-якої з двох паралельних задач.
            // Це гарантує, що при відключенні однієї сторони, інша також коректно завершить роботу.
            await Task.WhenAny(receiveTask, sendTask);
        }
    }
}

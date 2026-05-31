using System;
using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace SysMail
{
    /// <summary>
    /// Клас-контейнер, що зберігає мережевий та криптографічний контекст 
    /// кожного окремо підключеного клієнта.
    /// </summary>
    public class ClientConnection : CryptoSession
    {
        // Унікальний ідентифікатор клієнта (скорочений GUID для зручності відображення)
        public string Id { get; set; } = Guid.NewGuid().ToString().Substring(0, 4);

        // Мережевий TCP-потік для I/O операцій
        public NetworkStream Stream { get; set; } = null!;

        // Унікальний для кожного клієнта криптографічний контекст (ефемерні ключі, AEAD-стан)
        public CryptoSession Crypto { get; set; } = null!;

        // Лічильник очікуваних вхідних пакетів для захисту клієнтської лінії від Replay-атак
        public long InboundSequence { get; set; } = 0;

        // Внутрішній лічильник вихідних пакетів
        private long _outboundSequence = 0;

        /// <summary>
        /// Потокобезпечне (Thread-safe) отримання наступного номеру послідовності.
        /// Використовує апаратні атомарні операції Interlocked для уникнення 
        /// стану гонки (Race Condition) при паралельній розсилці повідомлень.
        /// </summary>
        public long GetNextOutboundSequence() => Interlocked.Increment(ref _outboundSequence) - 1;
    }

    /// <summary>
    /// Головний клас серверної підсистеми. Керує життєвим циклом підключень, 
    /// автентифікацією (X.509), захистом від MitM та багатопотоковою маршрутизацією повідомлень.
    /// </summary>
    public class SecureTcpServer : ClientConnection
    {
        // Потокобезпечна хеш-таблиця (словник) для зберігання об'єктів активних сесій.
        // Дозволяє додавати та видаляти клієнтів без блокування всього пулу потоків.
        private readonly ConcurrentDictionary<string, ClientConnection> _clients = new();

        // Довгостроковий сертифікат ідентичності сервера стандарту X.509
        private readonly X509Certificate2 _serverCertificate;

        // Приватний ключ сервера (ECDSA) для накладання цифрових підписів
        private readonly ECDsa _serverPrivateKey;

        /// <summary>
        /// Конструктор сервера. Виконує ініціалізацію інфраструктури відкритих ключів (PKI).
        /// </summary>
        public SecureTcpServer()
        {
            // Генерація довгострокової пари асиметричних ключів ECDSA (NIST P-256)
            _serverPrivateKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);

            // Створення та підпис власного (Self-signed) сертифіката X.509 
            // з терміном дії 1 рік. Використовується алгоритм хешування SHA-256.
            var request = new CertificateRequest("CN=SysMailServer", _serverPrivateKey, HashAlgorithmName.SHA256);
            _serverCertificate = request.CreateSelfSigned(DateTimeOffset.Now, DateTimeOffset.Now.AddYears(1));
        }

        public MessagePacket MessagePacket
        {
            get => default;
            set
            {
            }
        }

        /// <summary>
        /// Запускає асинхронне прослуховування вхідних підключень на вказаному порту.
        /// </summary>
        public async Task StartAsync(int port)
        {
            // Прив'язка TCP-прослуховувача до всіх доступних мережевих інтерфейсів (IPAddress.Any)
            TcpListener listener = new TcpListener(IPAddress.Any, port);
            listener.Start();

            ConsoleUI.PrintMessage($"[СЕРВЕР] Запущено на порту {port}");
            ConsoleUI.PrintMessage($"[СЕРВЕР] Сертифікат X.509 згенеровано.");
            ConsoleUI.PrintMessage("[СЕРВЕР] Очікування підключень...");
            Console.WriteLine("------------------------------------------------------------------");

            // Запуск окремого фонового завдання (Fire-and-Forget) для обробки 
            // вводу системних команд зі сторони адміністратора сервера.
            _ = Task.Run(AdminInputLoopAsync);

            // Нескінченний цикл акцептування нових клієнтських підключень
            while (true)
            {
                // Асинхронне очікування клієнта (повертає потік у ThreadPool доки немає активності)
                TcpClient tcpClient = await listener.AcceptTcpClientAsync();

                // Передача управління новим підключенням в окрему асинхронну задачу
                // Це дозволяє серверу миттєво повернутися до прослуховування наступних клієнтів
                _ = Task.Run(() => HandleClientAsync(tcpClient));
            }
        }

        /// <summary>
        /// Контролер життєвого циклу окремого підключеного клієнта.
        /// Реалізує кінцевий автомат: Handshake -> Authentication -> Main Loop -> Cleanup.
        /// </summary>
        private async Task HandleClientAsync(TcpClient tcpClient)
        {
            ClientConnection connection = new ClientConnection();

            try
            {
                connection.Stream = tcpClient.GetStream();
                connection.Crypto = new CryptoSession();

                // === ФАЗА 1. АВТЕНТИФІКАЦІЯ ТА ЗАХИСТ ВІД MitM ===

                // Отримання публічної частини ефемерного ключа сервера
                byte[] myEcdhPublicKey = connection.Crypto.GetPublicKey();

                // Експорт сертифіката сервера у форматі DER (X.509)
                byte[] certBytes = _serverCertificate.Export(X509ContentType.Cert);

                // КРИТИЧНИЙ ЕТАП БЕЗПЕКИ: Накладання цифрового підпису ECDSA 
                // на ефемерний ключ ECDH за допомогою приватного ключа сертифіката.
                byte[] signature = _serverPrivateKey.SignData(myEcdhPublicKey, HashAlgorithmName.SHA256);

                // Відправка автентифікаційного пакету клієнту
                await NetworkHelper.SendBytesAsync(connection.Stream, certBytes);
                await NetworkHelper.SendBytesAsync(connection.Stream, myEcdhPublicKey);
                await NetworkHelper.SendBytesAsync(connection.Stream, signature);

                // === ФАЗА 2. ОБМІН КЛЮЧАМИ ТА ДЕРИВАЦІЯ ===

                // Отримання публічного ключа клієнта
                byte[] clientPublicKey = await NetworkHelper.ReceiveBytesAsync(connection.Stream);

                // Деривація (математичне обчислення) симетричного сесійного ключа через HKDF
                connection.Crypto.DeriveSessionKey(clientPublicKey);

                // === ФАЗА 3. УЗГОДЖЕННЯ АЛГОРИТМУ ШИФРУВАННЯ (Cipher Suite Negotiation) ===

                byte[] clientSuitesBytes = await NetworkHelper.ReceiveBytesAsync(connection.Stream);
                string clientSuites = System.Text.Encoding.UTF8.GetString(clientSuitesBytes);

                string selectedSuite = "ChaCha20";

                // Перевірка, чи доступне апаратне прискорення AES-NI на процесорі сервера.
                // Якщо так, і клієнт підтримує AES, встановлюємо пріоритет на AES-256-GCM.
                if (clientSuites.Contains("AES-GCM") && AesGcm.IsSupported)
                {
                    selectedSuite = "AES-GCM";
                    connection.Crypto.SetCipherSuite(CipherSuite.Aes256Gcm);
                }
                else
                {
                    // Деградація до оптимізованого ChaCha20-Poly1305 для забезпечення продуктивності
                    connection.Crypto.SetCipherSuite(CipherSuite.ChaCha20Poly1305);
                }

                // Відправлення рішення щодо алгоритму клієнту
                await NetworkHelper.SendBytesAsync(connection.Stream, System.Text.Encoding.UTF8.GetBytes(selectedSuite));

                // Реєстрація клієнта у системі та розсилка системного повідомлення
                _clients.TryAdd(connection.Id, connection);
                ConsoleUI.PrintMessage($"[СЕРВЕР] Клієнт {connection.Id} підключився (Шифр: {selectedSuite}).");
                await BroadcastMessageAsync("СИСТЕМА", $"Користувач {connection.Id} приєднався до чату.", MessageType.System, connection.Id);

                // === ФАЗА 4. ОСНОВНИЙ ЦИКЛ ОБРОБКИ ПОВІДОМЛЕНЬ ===
                while (true)
                {
                    // Асинхронне читання зашифрованого блоку (Length-Prefix Framing)
                    byte[] encryptedData = await NetworkHelper.ReceiveBytesAsync(connection.Stream);

                    // Розшифровка та криптографічна автентифікація AEAD (перевірка MAC-тегу)
                    string json = connection.Crypto.DecryptData(encryptedData);

                    // Десеріалізація JSON-об'єкта у структуру DTO
                    MessagePacket? packet = JsonSerializer.Deserialize<MessagePacket>(json);
                    if (packet == null) continue;

                    // БЕЗПЕКА: ВАЛІДАЦІЯ СТАНУ (Replay Protection)
                    // Номер пакету має строго дорівнювати очікуваному внутрішньому лічильнику.
                    // Будь-яке відхилення свідчить про спробу атаки або серйозний збій мережі.
                    if (packet.SequenceNumber != connection.InboundSequence)
                    {
                        ConsoleUI.PrintMessage($"[СЕРВЕР] ❌ ПОПЕРЕДЖЕННЯ БЕЗПЕКИ: Клієнт {connection.Id} надіслав дубльований/підроблений пакет. З'єднання розірвано.");
                        break;  // Примусове розірвання скомпрометованої сесії
                    }
                    connection.InboundSequence++;   // Інкремент очікуваного номеру наступного пакету

                    // Обробка керуючих директив (Graceful Disconnect)
                    if (packet.Type == MessageType.Command && packet.Payload == "exit")
                    {
                        break;
                    }

                    // Пересилання текстових повідомлень усім іншим зареєстрованим клієнтам
                    if (packet.Type == MessageType.Text)
                    {
                        string timeInfo = packet.Timestamp.ToString("HH:mm:ss");
                        ConsoleUI.PrintMessage($"[{timeInfo}] [КЛІЄНТ {connection.Id}]: {packet.Payload}");

                        await BroadcastMessageAsync(connection.Id, packet.Payload, MessageType.Text, connection.Id);
                    }
                }
            }
            catch
            {
                // Тихе перехоплення мережевих винятків при раптовому обриві TCP-з'єднання (наприклад, втрата інтернету клієнтом)
            }
            finally
            {
                // === ФАЗА 5. ОЧИЩЕННЯ РЕСУРСІВ (Cleanup) ===

                // Видалення клієнта з потокобезпечного словника
                _clients.TryRemove(connection.Id, out _);

                // Виклик Dispose для гарантованого знищення 256-бітного ключа в оперативній пам'яті сервера
                connection.Crypto?.Dispose();

                // Закриття мережевого сокета
                tcpClient.Close();

                ConsoleUI.PrintMessage($"[СЕРВЕР] Клієнт {connection.Id} відключився. Всього онлайн: {_clients.Count}");
                await BroadcastMessageAsync("СИСТЕМА", $"Користувач {connection.Id} покинув чат.", MessageType.System, null);
            }
        }

        /// <summary>
        /// Відправляє повідомлення усім підключеним клієнтам, крім вказаного виключення (відправника).
        /// Оскільки кожен клієнт має власну сесію, повідомлення серіалізується та шифрується 
        /// ІНДИВІДУАЛЬНО для кожного одержувача з унікальними Nonce та SequenceNumber.
        /// </summary>
        private async Task BroadcastMessageAsync(string senderId, string payload, MessageType type, string? excludeClientId)
        {
            var packet = new MessagePacket
            {
                Type = type,
                Timestamp = DateTime.Now,
                SenderId = senderId,
                Payload = payload
            };

            foreach (var kvp in _clients)
            {
                if (kvp.Key == excludeClientId) continue;

                try
                {
                    // Атомарний інкремент вихідного лічильника індивідуально для контексту кожного підключення
                    packet.SequenceNumber = kvp.Value.GetNextOutboundSequence();

                    // Серіалізація об'єкта в текст
                    string json = JsonSerializer.Serialize(packet);

                    // Шифрування повідомлення унікальним ключем конкретного клієнта
                    byte[] encryptedData = kvp.Value.Crypto.EncryptData(json);

                    // Асинхронна відправка пакету в сокет
                    await NetworkHelper.SendBytesAsync(kvp.Value.Stream, encryptedData);
                }
                catch { }
            }
        }

        /// <summary>
        /// Асинхронний метод, що утримує цикл для обробки введення команд 
        /// безпосередньо у консолі адміністратора сервера.
        /// </summary>
        private async Task AdminInputLoopAsync()
        {
            while (true)
            {
                string input = ConsoleUI.ReadLine();
                if (string.IsNullOrWhiteSpace(input)) continue;

                if (input == "/exit")
                {
                    ConsoleUI.PrintMessage("[СЕРВЕР] Завершення роботи...");
                    Environment.Exit(0);
                }

                // Розсилка повідомлення адміністратора всім користувачам мережі
                await BroadcastMessageAsync("АДМІН", input, MessageType.Text, null);
            }
        }
    }
}

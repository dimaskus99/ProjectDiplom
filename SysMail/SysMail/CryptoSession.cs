using System;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;

namespace SysMail
{
    /// <summary>
    /// Перелічення підтримуваних наборів симетричних шифрів (AEAD).
    /// Дозволяє реалізувати механізм узгодження шифрів (Cipher Suite Negotiation).
    /// </summary>
    public enum CipherSuite
    {
        Aes256Gcm,          // Апаратно-прискорений алгоритм AES у режимі Галуа/Лічильника
        ChaCha20Poly1305    // Програмно-оптимізований потоковий алгоритм
    }

    /// <summary>
    /// Ядро криптографічної безпеки. Інкапсулює життєвий цикл ключів,
    /// деривацію спільного секрету та операції AEAD-шифрування.
    /// Реалізує інтерфейс IDisposable для гарантованого очищення конфіденційного
    /// матеріалу з пам'яті після закриття сесії.
    /// </summary>
    public class CryptoSession : IDisposable
    {
        // Об'єкт для реалізації обміну ключами Діффі-Геллмана на еліптичних кривих
        private readonly ECDiffieHellman _ecdh;

        // Фінальний симетричний 256-бітний ключ сесії, згенерований через HKDF
        private byte[]? _sessionKey;

        // Властивість для збереження останнього вектору ініціалізації (Nonce)
        // Використовується виключно для цілей діагностики та команди /crypto
        public byte[]? LastNonce { get; private set; }

        // Метрика продуктивності: час у мілісекундах, витрачений на складну математику деривації
        public long KeyDerivationTimeMs { get; private set; }

        // Обраний криптонабір (за замовчуванням AES-256-GCM як індустріальний стандарт)
        public CipherSuite SelectedCipher { get; private set; } = CipherSuite.Aes256Gcm;

        public CipherSuite CipherSuite
        {
            get => default;
            set
            {
            }
        }

        /// <summary>
        /// Конструктор класу. Створює нову ефемерну ключову пару для забезпечення PFS.
        /// </summary>
        public CryptoSession()
        {
            // Ініціалізація ефемерної пари ключів на стандартизованій кривій NIST P-256
            _ecdh = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        }

        /// <summary>
        /// Експорт публічної частини ефемерного ключа у стандартному форматі 
        /// SubjectPublicKeyInfo для передачі віддаленій стороні під час Handshake.
        /// </summary>
        public byte[] GetPublicKey() =>
            _ecdh.PublicKey.ExportSubjectPublicKeyInfo();

        /// <summary>
        /// Динамічно встановлює алгоритм шифрування після його узгодження з сервером.
        /// </summary>
        public void SetCipherSuite(CipherSuite suite)
        {
            SelectedCipher = suite;
        }

        /// <summary>
        /// Обчислює загальний спільний секрет на базі отриманого чужого публічного ключа
        /// та виконує криптографічну деривацію фінального сесійного ключа.
        /// </summary>
        /// <param name="otherPartyPublicKeyInfo">Байтове представлення відкритого ключа партнера.</param>
        public void DeriveSessionKey(byte[] otherPartyPublicKeyInfo)
        {
            var sw = Stopwatch.StartNew();

            // Створення тимчасового об'єкта для імпорту чужого відкритого ключа
            using var otherPartyKey = ECDiffieHellman.Create();
            otherPartyKey.ImportSubjectPublicKeyInfo(otherPartyPublicKeyInfo, out _);

            // МАТЕМАТИЧНЕ ОБЧИСЛЕННЯ: Отримання сирого спільного секрету (Raw Shared Secret)
            // через скалярне множення свого приватного ключа на чужий публічний ключ.
            byte[] rawSecret = _ecdh.DeriveKeyMaterial(otherPartyKey.PublicKey);

            // ДЕРИВАЦІЯ КЛЮЧА: Функція формування ключа HKDF (витяг та розширення) з SHA-256
            // "Розтягує" та рівномірно розподіляє ентропію, генеруючи ідеальний 32-байтовий ключ
            _sessionKey = HKDF.DeriveKey(
                HashAlgorithmName.SHA256,
                rawSecret,
                32,     // Необхідна довжина вихідного ключа (256 біт)
                null,   // Опціональна криптографічна сіль (не використовується)
                null    // Опціональна інформація контексту (не використовується)
            );

            // КРИТИЧНО ДЛЯ БЕЗПЕКИ: Примусове затирання сирого секрету нулями.
            // Захищає від атак, спрямованих на читання дампу оперативної пам'яті.
            CryptographicOperations.ZeroMemory(rawSecret);

            sw.Stop();
            KeyDerivationTimeMs = sw.ElapsedMilliseconds;
        }

        /// <summary>
        /// Здійснює автентифіковане шифрування відкритого тексту.
        /// Формує єдиний пакет, що містить Nonce, Tag та Шифротекст.
        /// </summary>
        /// <param name="plaintext">Текст повідомлення у форматі JSON.</param>
        /// <returns>Байтовий масив, готовий для відправки по мережі.</returns>
        public byte[] EncryptData(string plaintext)
        {
            if (_sessionKey == null) throw new InvalidOperationException("Ключ сесії не встановлено.");

            // Перетворення Unicode-рядка у масив байтів (UTF-8)
            byte[] plaintextBytes = Encoding.UTF8.GetBytes(plaintext);

            // Стандартні розміри криптографічних параметрів для GCM та Poly1305
            int nonceLength = 12;   // 96-бітний вектор ініціалізації
            int tagLength = 16;     // 128-бітний код автентифікації повідомлення (MAC)

            // Формування єдиного вихідного масиву: [Nonce (12)] + + [Ciphertext (N)]
            byte[] payload = new byte[nonceLength + tagLength + plaintextBytes.Length];

            // ОПТИМІЗАЦІЯ ПАМ'ЯТІ: Використання Span для високопродуктивного доступу 
            // до сегментів масиву без додаткових алокацій та викликів збирача сміття (GC).
            Span<byte> payloadSpan = payload;

            // Створення "вікон" (слайсів) у єдиному масиві payload
            Span<byte> nonceSpan = payloadSpan.Slice(0, nonceLength);
            Span<byte> tagSpan = payloadSpan.Slice(nonceLength, tagLength);
            Span<byte> cipherSpan = payloadSpan.Slice(nonceLength + tagLength, plaintextBytes.Length);

            // Генерація криптографічно безпечного випадкового Nonce
            RandomNumberGenerator.Fill(nonceSpan);
            LastNonce = nonceSpan.ToArray();    // Збереження копії для команди /crypto

            // Динамічний вибір алгоритму шифрування на основі патерну "Стратегія"
            if (SelectedCipher == CipherSuite.Aes256Gcm)
            {
                // Створення об'єкта AES-GCM (автоматично звільняється завдяки 'using var')
                using var aes = new AesGcm(_sessionKey, tagLength);

                // Однопрохідне шифрування та обчислення MAC-тегу
                // Результати записуються безпосередньо у відповідні слайси масиву payload
                aes.Encrypt(nonceSpan, plaintextBytes, cipherSpan, tagSpan);
            }
            else
            {
                using var chacha = new ChaCha20Poly1305(_sessionKey);
                chacha.Encrypt(nonceSpan, plaintextBytes, cipherSpan, tagSpan);
            }

            return payload;
        }

        /// <summary>
        /// Розшифровує повідомлення та автоматично криптографічно верифікує тег автентифікації.
        /// </summary>
        /// <param name="payload">Зашифрований мережевий пакет.</param>
        /// <returns>Відновлений відкритий рядок.</returns>
        public string DecryptData(byte[] payload)
        {
            if (_sessionKey == null) throw new InvalidOperationException("Ключ сесії не встановлено.");

            // Використання ReadOnlySpan для безпечного та швидкого розбору вхідного пакета
            ReadOnlySpan<byte> payloadSpan = payload;

            int nonceLength = 12;
            int tagLength = 16;

            // Слайсинг вхідного буфера на логічні складові
            ReadOnlySpan<byte> nonceSpan = payloadSpan.Slice(0, nonceLength);
            ReadOnlySpan<byte> tagSpan = payloadSpan.Slice(nonceLength, tagLength);
            ReadOnlySpan<byte> cipherSpan = payloadSpan.Slice(nonceLength + tagLength);

            // Виділення пам'яті під розшифрований текст (довжина відповідає довжині шифротексту)
            byte[] plaintextBytes = new byte[cipherSpan.Length];

            // РОЗШИФРУВАННЯ ТА ВАЛІДАЦІЯ: 
            // Алгоритм AEAD автоматично перевіряє цілісність даних за допомогою tagSpan.
            // Якщо хоча б один біт у шифротексті або тезі був змінений, метод викине 
            // CryptographicException, і розшифровані дані не будуть надані системі.
            if (SelectedCipher == CipherSuite.Aes256Gcm)
            {
                using var aes = new AesGcm(_sessionKey, tagLength);
                aes.Decrypt(nonceSpan, cipherSpan, tagSpan, plaintextBytes);
            }
            else
            {
                using var chacha = new ChaCha20Poly1305(_sessionKey);
                chacha.Decrypt(nonceSpan, cipherSpan, tagSpan, plaintextBytes);
            }

            // Зворотнє перетворення UTF-8 байтів у.NET рядок
            return Encoding.UTF8.GetString(plaintextBytes);
        }

        /// <summary>
        /// Імплементація інтерфейсу IDisposable. 
        /// Виклик методу гарантує, що конфіденційні ключі не залишаться 
        /// в оперативній пам'яті як сміття після закриття TCP-з'єднання.
        /// </summary>
        public void Dispose()
        {
            if (_sessionKey != null)
            {
                // Примусове затирання сесійного ключа
                CryptographicOperations.ZeroMemory(_sessionKey);
            }

            // Звільнення ресурсів математичного апарату ECDH
            _ecdh.Dispose();
        }
    }
}
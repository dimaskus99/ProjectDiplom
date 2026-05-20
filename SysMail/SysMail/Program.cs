using System;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace SysMail
{
    // ==========================================================
    // 1. КРИПТОГРАФІЧНИЙ МОДУЛЬ
    // ==========================================================
    public class CryptoSession : IDisposable
    {
        private readonly ECDiffieHellman _ecdh;
        private byte[] _sessionKey;

        public CryptoSession()
        {
            _ecdh = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        }

        public byte[] GetPublicKey() =>
            _ecdh.PublicKey.ExportSubjectPublicKeyInfo();

        public void DeriveSessionKey(byte[] otherPartyPublicKeyInfo)
        {
            using var otherPartyKey = ECDiffieHellman.Create();

            otherPartyKey.ImportSubjectPublicKeyInfo(
                otherPartyPublicKeyInfo,
                out _
            );

            byte[] rawSecret =
                _ecdh.DeriveKeyMaterial(otherPartyKey.PublicKey);

            _sessionKey = HKDF.DeriveKey(
                HashAlgorithmName.SHA256,
                rawSecret,
                32,
                null,
                null
            );

            CryptographicOperations.ZeroMemory(rawSecret);
        }

        public byte[] EncryptData(string plaintext)
        {
            byte[] plaintextBytes = Encoding.UTF8.GetBytes(plaintext);

            byte[] nonce = new byte[12];
            RandomNumberGenerator.Fill(nonce);

            byte[] ciphertext = new byte[plaintextBytes.Length];
            byte[] tag = new byte[16];

            using var aes = new AesGcm(_sessionKey, tag.Length);

            aes.Encrypt(nonce, plaintextBytes, ciphertext, tag);

            byte[] payload =
                new byte[nonce.Length + tag.Length + ciphertext.Length];

            Buffer.BlockCopy(nonce, 0, payload, 0, nonce.Length);
            Buffer.BlockCopy(tag, 0, payload, nonce.Length, tag.Length);
            Buffer.BlockCopy(
                ciphertext,
                0,
                payload,
                nonce.Length + tag.Length,
                ciphertext.Length
            );

            return payload;
        }

        public string DecryptData(byte[] payload)
        {
            byte[] nonce = new byte[12];
            byte[] tag = new byte[16];
            byte[] ciphertext =
                new byte[payload.Length - nonce.Length - tag.Length];

            Buffer.BlockCopy(payload, 0, nonce, 0, nonce.Length);
            Buffer.BlockCopy(payload, nonce.Length, tag, 0, tag.Length);
            Buffer.BlockCopy(
                payload,
                nonce.Length + tag.Length,
                ciphertext,
                0,
                ciphertext.Length
            );

            byte[] plaintextBytes = new byte[ciphertext.Length];

            using var aes = new AesGcm(_sessionKey, tag.Length);

            aes.Decrypt(nonce, ciphertext, tag, plaintextBytes);

            return Encoding.UTF8.GetString(plaintextBytes);
        }

        public void Dispose()
        {
            if (_sessionKey != null)
            {
                CryptographicOperations.ZeroMemory(_sessionKey);
            }

            _ecdh.Dispose();
        }
    }

    // ==========================================================
    // 2. ДОПОМІЖНІ МЕТОДИ
    // ==========================================================
    public static class NetworkHelper
    {
        public static async Task SendBytesAsync(
            NetworkStream stream,
            byte[] data)
        {
            byte[] length = BitConverter.GetBytes(data.Length);

            await stream.WriteAsync(length, 0, 4);
            await stream.WriteAsync(data, 0, data.Length);
        }

        public static async Task<byte[]> ReceiveBytesAsync(
            NetworkStream stream)
        {
            byte[] lengthBytes = new byte[4];

            await ReadExactAsync(stream, lengthBytes, 4);

            int length = BitConverter.ToInt32(lengthBytes, 0);

            byte[] data = new byte[length];

            await ReadExactAsync(stream, data, length);

            return data;
        }

        public static async Task ReadExactAsync(
            NetworkStream stream,
            byte[] buffer,
            int length)
        {
            int totalRead = 0;

            while (totalRead < length)
            {
                int bytesRead = await stream.ReadAsync(
                    buffer,
                    totalRead,
                    length - totalRead
                );

                if (bytesRead == 0)
                    throw new Exception("З'єднання закрито.");

                totalRead += bytesRead;
            }
        }
    }

    // ==========================================================
    // 3. СЕРВЕР
    // ==========================================================
    public class SecureTcpServer
    {
        public async Task StartAsync(int port)
        {
            TcpListener listener =
                new TcpListener(IPAddress.Any, port);

            listener.Start();

            Console.WriteLine($"[СЕРВЕР] Запущено на порту {port}");
            Console.WriteLine("[СЕРВЕР] Очікування клієнта...");

            using TcpClient client =
                await listener.AcceptTcpClientAsync();

            Console.WriteLine("[СЕРВЕР] Клієнт підключився.");

            using NetworkStream stream = client.GetStream();
            using CryptoSession crypto = new CryptoSession();

            // HANDSHAKE
            byte[] myPublicKey = crypto.GetPublicKey();
            await NetworkHelper.SendBytesAsync(stream, myPublicKey);

            byte[] clientPublicKey =
                await NetworkHelper.ReceiveBytesAsync(stream);

            crypto.DeriveSessionKey(clientPublicKey);

            Console.WriteLine("[СЕРВЕР] Захищений канал встановлено.");

            // ЧАТ
            while (true)
            {
                try
                {
                    byte[] encryptedMessage =
                        await NetworkHelper.ReceiveBytesAsync(stream);

                    string message =
                        crypto.DecryptData(encryptedMessage);

                    if (message == "/exit")
                    {
                        Console.WriteLine("[СЕРВЕР] Клієнт завершив сеанс.");
                        break;
                    }

                    Console.WriteLine($"\n[КЛІЄНТ]: {message}");

                    Console.Write("[ВИ]: ");
                    string response = Console.ReadLine();

                    byte[] encryptedResponse =
                        crypto.EncryptData(response);

                    await NetworkHelper.SendBytesAsync(
                        stream,
                        encryptedResponse
                    );

                    if (response == "/exit")
                        break;
                }
                catch
                {
                    Console.WriteLine("\n[СЕРВЕР] З'єднання втрачено.");
                    break;
                }
            }

            listener.Stop();
        }
    }

    // ==========================================================
    // 4. КЛІЄНТ
    // ==========================================================
    public class SecureTcpClient
    {
        public async Task StartAsync(string ip, int port)
        {
            using TcpClient client = new TcpClient();

            await client.ConnectAsync(ip, port);

            Console.WriteLine($"[КЛІЄНТ] Підключено до {ip}:{port}");

            using NetworkStream stream = client.GetStream();
            using CryptoSession crypto = new CryptoSession();

            // HANDSHAKE
            byte[] serverPublicKey =
                await NetworkHelper.ReceiveBytesAsync(stream);

            byte[] myPublicKey = crypto.GetPublicKey();

            await NetworkHelper.SendBytesAsync(stream, myPublicKey);

            crypto.DeriveSessionKey(serverPublicKey);

            Console.WriteLine("[КЛІЄНТ] Захищений канал встановлено.");
            Console.WriteLine("Введіть повідомлення.");
            Console.WriteLine("Для виходу введіть /exit");

            // ЧАТ
            while (true)
            {
                Console.Write("\n[ВИ]: ");

                string message = Console.ReadLine();

                byte[] encryptedMessage =
                    crypto.EncryptData(message);

                await NetworkHelper.SendBytesAsync(
                    stream,
                    encryptedMessage
                );

                if (message == "/exit")
                    break;

                try
                {
                    byte[] encryptedResponse =
                        await NetworkHelper.ReceiveBytesAsync(stream);

                    string response =
                        crypto.DecryptData(encryptedResponse);

                    Console.WriteLine($"\n[СЕРВЕР]: {response}");

                    if (response == "/exit")
                        break;
                }
                catch
                {
                    Console.WriteLine("[КЛІЄНТ] Сервер відключився.");
                    break;
                }
            }
        }
    }

    // ==========================================================
    // 5. ГОЛОВНЕ МЕНЮ
    // ==========================================================
    class Program
    {
        static async Task Main()
        {
            Console.OutputEncoding = Encoding.UTF8;

            Console.WriteLine("====================================");
            Console.WriteLine("  SECURE REMOTE COMMUNICATION");
            Console.WriteLine("====================================");

            Console.WriteLine("1 - Запустити сервер");
            Console.WriteLine("2 - Запустити клієнт");

            Console.Write("\nВаш вибір: ");

            string choice = Console.ReadLine();

            int port = 5000;

            if (choice == "1")
            {
                SecureTcpServer server =
                    new SecureTcpServer();

                await server.StartAsync(port);
            }
            else if (choice == "2")
            {
                Console.Write("IP сервера: ");
                string ip = Console.ReadLine();

                SecureTcpClient client =
                    new SecureTcpClient();

                await client.StartAsync(ip, port);
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
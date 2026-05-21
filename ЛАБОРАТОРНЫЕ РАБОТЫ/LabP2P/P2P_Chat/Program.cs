using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;

namespace P2PChat
{
    enum MessageType : byte
    {
        Handshake = 1,
        TextMessage = 2,
        HistoryRequest = 3,
        HistoryResponse = 4
    }

    class Program
    {
        private static string _localIp;
        private static int _udpPort;
        private static int _tcpPort;
        private static string _localName;

        private static ConcurrentDictionary<string, NetworkStream> _peers = new();
        private static List<string> _history = new();
        private static readonly object _historyLock = new();
        private static bool _historyReceived = false;

        static async Task Main(string[] args)
        {
            TcpListener tcpListener = null;

            
            while (true)
            {
                Console.Write("Введите IP: ");
                _localIp = Console.ReadLine()?.Trim() ?? "127.0.0.1";
                if (string.IsNullOrEmpty(_localIp)) _localIp = "127.0.0.1";

                Console.Write("Введите UDP порт: ");
                if (!int.TryParse(Console.ReadLine(), out _udpPort)) _udpPort = 8888;

                Console.Write("Введите TCP порт: ");
                if (!int.TryParse(Console.ReadLine(), out _tcpPort)) _tcpPort = 8889;

                Console.Write("Введите имя: ");
                _localName = Console.ReadLine()?.Trim() ?? "Unknown";
                if (string.IsNullOrEmpty(_localName)) _localName = "Unknown";

                try
                {
                    
                    tcpListener = new TcpListener(IPAddress.Parse(_localIp), _tcpPort);
                    tcpListener.Start();

                    break;
                }
                catch (SocketException ex)
                {
                    Console.ForegroundColor = ConsoleColor.Red;
                    if (ex.SocketErrorCode == SocketError.AddressAlreadyInUse)
                    {
                        Console.WriteLine($"\n[ОШИБКА] Этот IP ({_localIp}) и порт ({_tcpPort}) уже заняты другой копией чата!");
                    }
                    else if (ex.SocketErrorCode == SocketError.AddressNotAvailable)
                    {
                        Console.WriteLine($"\n[ОШИБКА] IP-адрес {_localIp} не принадлежит вашему компьютеру!");
                    }
                    else
                    {
                        Console.WriteLine($"\n[ОШИБКА] Сетевая ошибка: {ex.Message}");
                    }
                    Console.ResetColor();
                    Console.WriteLine("Пожалуйста, введите другие данные.\n" + new string('-', 40));
                }
                catch (FormatException)
                {
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine("\n[ОШИБКА] Неверный формат IP-адреса! Попробуйте еще раз.\n" + new string('-', 40));
                    Console.ResetColor();
                }
            }

            Console.Clear();
            PrintSystemMessage($"Запуск узла [{_localName}] на {_localIp} (UDP: {_udpPort}, TCP: {_tcpPort})...");

            _ = Task.Run(() => StartTcpServer(tcpListener));
            _ = Task.Run(() => StartUdpListener());
            BroadcastPresence();
            

            Console.WriteLine("Чат готов к работе. Для вывода истории введите /log\n" + new string('-', 40));

            while (true)
            {
                string input = Console.ReadLine();
                if (string.IsNullOrWhiteSpace(input)) continue;

                if (input.Contains("/log"))
                {
                    ShowLogs();
                    continue;
                }

                string displayMsg = $"{_localIp} <{_localName}>: \"{input}\"";

                Console.SetCursorPosition(0, Console.CursorTop - 1);
                Console.WriteLine(displayMsg);
                AddToHistory(displayMsg);

                await BroadcastTcpMessage(MessageType.TextMessage, input);
            }
        }

        #region Логика отображения и истории
        private static void PrintSystemMessage(string message)
        {
            Console.WriteLine(message);
            AddToHistory(message);
        }

        private static void AddToHistory(string entry)
        {
            string timeStampedEntry = $"[{DateTime.Now:HH:mm:ss}] {entry}";
            lock (_historyLock) { _history.Add(timeStampedEntry); }
        }

        private static void ShowLogs()
        {
            Console.WriteLine("\n=== ЛОГ СОБЫТИЙ ===");
            lock (_historyLock)
            {
                if (_history.Count == 0) Console.WriteLine("История пуста.");
                else foreach (var item in _history) Console.WriteLine(item);
            }
            Console.WriteLine("===================\n");
        }
        #endregion

        #region UDP Discovery
        private static void BroadcastPresence()
        {
            try
            {
            
                using UdpClient udpClient = new UdpClient(new IPEndPoint(IPAddress.Parse(_localIp), 0));
                udpClient.EnableBroadcast = true;
                byte[] nameBytes = Encoding.UTF8.GetBytes(_localName);
                IPEndPoint endPoint = new IPEndPoint(IPAddress.Broadcast, _udpPort);
                udpClient.Send(nameBytes, nameBytes.Length, endPoint);
            }
            catch (Exception ex)
            {
                PrintSystemMessage($"Ошибка UDP рассылки: {ex.Message}");
            }
        }

        private static async Task StartUdpListener()
        {
            using UdpClient udpServer = new UdpClient();
            udpServer.Client.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
            udpServer.Client.Bind(new IPEndPoint(IPAddress.Any, _udpPort));

            while (true)
            {
                var result = await udpServer.ReceiveAsync();
                string senderIp = result.RemoteEndPoint.Address.ToString();
                string senderName = Encoding.UTF8.GetString(result.Buffer);

                if (senderIp == _localIp) continue;

                if (!_peers.ContainsKey(senderIp))
                {
                    PrintSystemMessage($"Обнаружен узел {senderName} ({senderIp}). Подключаемся...");
                    _ = ConnectToPeer(senderIp);
                }
            }
        }
        #endregion

        #region TCP Networking
        
        private static async Task StartTcpServer(TcpListener listener)
        {
            while (true)
            {
                TcpClient client = await listener.AcceptTcpClientAsync();
                string remoteIp = ((IPEndPoint)client.Client.RemoteEndPoint).Address.ToString();
                _ = HandlePeerConnection(client, remoteIp, isIncoming: true);
            }
        }

        private static async Task ConnectToPeer(string ip)
        {
            try
            {
               
                IPEndPoint localEndPoint = new IPEndPoint(IPAddress.Parse(_localIp), 0);
                TcpClient client = new TcpClient(localEndPoint);

                await client.ConnectAsync(IPAddress.Parse(ip), _tcpPort);
                _ = HandlePeerConnection(client, ip, isIncoming: false);
            }
            catch (Exception ex)
            {
                PrintSystemMessage($"Ошибка подключения к {ip}: {ex.Message}");
            }
        }

        private static async Task HandlePeerConnection(TcpClient client, string remoteIp, bool isIncoming)
        {
            NetworkStream stream = client.GetStream();

            if (!_peers.TryAdd(remoteIp, stream))
            {
                client.Close();
                return;
            }

            string remoteName = "Unknown";

            try
            {
                await SendMessageAsync(stream, MessageType.Handshake, _localName);

                if (isIncoming && !_historyReceived)
                {
                    _historyReceived = true;
                    await SendMessageAsync(stream, MessageType.HistoryRequest, "Req");
                }

                while (true)
                {
                    byte[] header = new byte[5];
                    if (!await ReadExactlyAsync(stream, header, 5)) break;

                    MessageType type = (MessageType)header[0];
                    int length = BitConverter.ToInt32(header, 1);

                    byte[] payload = new byte[length];
                    if (!await ReadExactlyAsync(stream, payload, length)) break;

                    string data = Encoding.UTF8.GetString(payload);

                    switch (type)
                    {
                        case MessageType.Handshake:
                            remoteName = data;
                            PrintSystemMessage($"Узел {remoteName} ({remoteIp}) присоединился к чату.");
                            break;

                        case MessageType.TextMessage:
                            string displayMsg = $"{remoteIp} <{remoteName}>: \"{data}\"";
                            Console.WriteLine(displayMsg);
                            AddToHistory(displayMsg);
                            break;

                        case MessageType.HistoryRequest:
                            string historyJson;
                            lock (_historyLock) { historyJson = JsonSerializer.Serialize(_history); }
                            await SendMessageAsync(stream, MessageType.HistoryResponse, historyJson);
                            break;

                        case MessageType.HistoryResponse:
                            var receivedHistory = JsonSerializer.Deserialize<List<string>>(data);
                            if (receivedHistory != null && receivedHistory.Count > 0)
                            {
                                Console.WriteLine("\n--- ИСТОРИЯ ЗАГРУЖЕНА ---");
                                foreach (var item in receivedHistory)
                                {
                                    Console.WriteLine(item);
                                    lock (_historyLock) { _history.Add(item); }
                                }
                                Console.WriteLine("-------------------------\n");
                            }
                            break;
                    }
                }
            }
            catch (Exception) { }
            finally
            {
                _peers.TryRemove(remoteIp, out _);
                client.Close();
                PrintSystemMessage($"Узел {remoteName} ({remoteIp}) отключился.");
            }
        }

        private static async Task BroadcastTcpMessage(MessageType type, string text)
        {
            foreach (var peer in _peers.Values)
            {
                try { await SendMessageAsync(peer, type, text); }
                catch { }
            }
        }
        #endregion

        #region Протокол
        private static async Task SendMessageAsync(NetworkStream stream, MessageType type, string data)
        {
            byte[] payload = Encoding.UTF8.GetBytes(data);
            byte[] lengthBytes = BitConverter.GetBytes(payload.Length);

            byte[] packet = new byte[1 + 4 + payload.Length];
            packet[0] = (byte)type;
            Buffer.BlockCopy(lengthBytes, 0, packet, 1, 4);
            Buffer.BlockCopy(payload, 0, packet, 5, payload.Length);

            await stream.WriteAsync(packet, 0, packet.Length);
        }

        private static async Task<bool> ReadExactlyAsync(NetworkStream stream, byte[] buffer, int count)
        {
            int offset = 0;
            while (offset < count)
            {
                int read = await stream.ReadAsync(buffer, offset, count - offset);
                if (read == 0) return false;
                offset += read;
            }
            return true;
        }
        #endregion
    }
}
using System;
using System.Collections;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading.Tasks;

namespace server
{
    public enum MessageType : byte
    {

        ConnectionRequest = 0,  // Клиент -> Сервер: 
        ConnectionAccept = 1,   // Сервер -> Клиент: 
        Disconnect = 2,         // Любой -> Любой: 

        PlayerInput = 3,        // Клиент -> Сервер: 
        WorldState = 4,         // Сервер -> Клиент: 

        PlayerJoined = 5,       // Сервер -> Клиент:
        PlayerLeft = 6,         // Сервер -> Клиент:

        MatchResult = 7,        // Сервер -> Клиент:
        ReadyUpdate = 8,        // Клиент -> Сервер:
        MatchRestart = 9        // Сервер -> Клиент:
    }

    public enum Directions : byte
    {
        Up = 0,
        Down = 1,
        Left = 2,
        Right = 3,
    }

    public enum Input : byte
    {
        Up = 0,
        Down = 1,
        Left = 2,
        Right = 3,
        NoInput = 4,
        Shoot = 5
    }

    public enum CollisionResult
    {
        None,
        Tank,
        Wall
    }
    internal class Client
    {
        public string Name;
        public int ID;
        public Socket ClientSocket;

        public Client(string _name, int _id, Socket _socket)
        {
            Name = _name;
            ID = _id;
            ClientSocket = _socket;
        }
    }

    internal class Tank
    {
        public int PlayerID;
        public int x, y;
        public Directions Direction = Directions.Up;
        public int vx = 0, vy = 0;
        public int Score = 0;
        public int DeathCount = 0;

        public bool IsAlive = true;
        public int Health = 100;

        public int CooldownMs = 2000;
        public DateTime LastShotTime = DateTime.MinValue;

        public int Size = 40;

        public int sx, sy;

        public DateTime DeathTime;

        public Tank(int _id, int _x, int _y, Directions _direction)
        {
            PlayerID = _id;
            x = _x;
            y = _y;
            sx = _x;
            sy = _y;
            Direction = _direction;
        }
    }

    internal class Bullet
    {
        public int OwnerID;
        public int selfID;
        public int x, y;
        public int vx, vy;
        public int Size = 10;
        public Directions Direction;

        public Bullet(int _ownerID, int _selfID, int _x, int _y, int _vx, int _vy, Directions _direction)
        {
            OwnerID = _ownerID;
            selfID = _selfID;
            x = _x;
            y = _y;
            vx = _vx;
            vy = _vy;
            Direction = _direction;

        }


    }

    internal class server
    {

        static bool isMatchActive = true;
        static bool waitingForRematch = false;

        static Dictionary<int, bool> readyStatus = new Dictionary<int, bool>();

        static int matchDuration = 30;
        static int currentMatchTime = 0;

        static int winScore = 10;

        static DateTime lastMatchTick;



        static IPAddress srcIP = IPAddress.Parse("127.0.0.10");

        static ushort serverUdpPort = 8888;
        static ushort serverTcpPort = 9999;
        ushort dstTcpPort;

        static string serverName = "SERVER1";

        static int playersCount = 0;

        static List<Bullet> bullets = new List<Bullet>();

        static Client?[] clients = new Client?[4];
        static Tank?[] tanks = new Tank?[4];

        static GameMap currentMap = new GameMap("Maps/map1.txt");


        static int baseSpeed = 5;
        static int BulletSpeed = 15;

        static int bulletSize = 10;

        static int respawnTime = 10000;

        static int bulletIdHandler = 0;

        static string mapPath = "Maps/map1.txt";

        static void Main(string[] args)
        {

            try
            {
                ParseArguments(args);

                Task tcpListener = Task.Run(() => StartListener());
                Task broadcast = Task.Run(() => UdpBroadcast(srcIP));
                Task worldLoop = Task.Run(() => GameLifetimeLoop());
                Task dataBroadcast = Task.Run(() => StartPlayerDataBroadcast());

                Task.WaitAll(broadcast, tcpListener, worldLoop, dataBroadcast);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Ошибка: {ex}");
                Console.WriteLine("Нажмите Enter для выхода...");
                Console.ReadLine();
            }


        }

        static void ParseArguments(string[] args)
        {
            for (int i = 0; i < args.Length; i++)
            {
                switch (args[i].ToLower())
                {
                    case "-ip":
                        if (i + 1 < args.Length)
                        {
                            string ipStr = args[++i];
                            if (ipStr.Equals("any", StringComparison.OrdinalIgnoreCase))
                                srcIP = IPAddress.Any;
                            else if (IPAddress.TryParse(ipStr, out IPAddress parsedIp))
                                srcIP = parsedIp;
                            else
                                Console.WriteLine($"Некорректный IP: {ipStr}. Использую значение по умолчанию {srcIP}");
                        }
                        break;
                    case "-tcp":
                        if (i + 1 < args.Length && ushort.TryParse(args[++i], out ushort tcpPort))
                            serverTcpPort = tcpPort;
                        else
                            Console.WriteLine("Некорректный TCP порт. Использую значение по умолчанию");
                        break;
                    case "-udp":
                        if (i + 1 < args.Length && ushort.TryParse(args[++i], out ushort udpPort))
                            serverUdpPort = udpPort;
                        else
                            Console.WriteLine("Некорректный UDP порт. Использую значение по умолчанию");
                        break;
                    case "-name":
                        if (i + 1 < args.Length)
                            serverName = args[++i];
                        else
                            Console.WriteLine("Имя сервера не указано. Использую значение по умолчанию");
                        break;
                    case "-duration":
                        if (i + 1 < args.Length && int.TryParse(args[++i], out int duration) && duration > 0)
                            matchDuration = duration;
                        else
                            Console.WriteLine("Некорректная длительность матча. Использую значение по умолчанию");
                        break;
                    case "-target":
                        if (i + 1 < args.Length && int.TryParse(args[++i], out int target))
                            winScore = target;
                        else
                            Console.WriteLine("Некорректное значение цели. Использую значение по умолчанию 5");
                        break;
                    case "-map":
                        if (i + 1 < args.Length)
                        {
                            mapPath = args[++i];
                            if (File.Exists(mapPath))
                                currentMap = new GameMap(mapPath);
                            else
                                Console.WriteLine($"Файл карты {mapPath} не найден. Использую карту по умолчанию");
                        }
                        break;
                    case "-help":
                        PrintHelp();
                        Environment.Exit(0);
                        break;
                    default:
                        Console.WriteLine($"Неизвестный параметр: {args[i]}");
                        PrintHelp();
                        Environment.Exit(1);
                        break;
                }
            }

            Console.WriteLine($"Сервер запущен с параметрами:");
            Console.WriteLine($"  IP: {(srcIP == IPAddress.Any ? "any (0.0.0.0)" : srcIP.ToString())}");
            Console.WriteLine($"  TCP порт: {serverTcpPort}");
            Console.WriteLine($"  UDP порт: {serverUdpPort}");
            Console.WriteLine($"  Имя: {serverName}");
            Console.WriteLine($"  Длительность матча: {matchDuration} сек");
            Console.WriteLine($"  Карта: {currentMap.width}x{currentMap.height}");
        }

        static void PrintHelp()
        {
            Console.WriteLine(@"
                Использование: server.exe [параметры]

                Параметры:
                  -ip <адрес>      IP-адрес для привязки (можно 'any' или конкретный, например 192.168.1.100)
                  -tcp <порт>      TCP порт для подключений (по умолчанию 9999)
                  -udp <порт>      UDP порт для broadcast (по умолчанию 8888)
                  -name <имя>      Имя сервера (отображается в списке)
                  -duration <сек>  Длительность матча в секундах
                  -map <путь>      Путь к файлу карты (текстовый файл)
                  -help            Показать эту справку

                Пример:
                  server.exe -ip 192.168.1.100 -tcp 9999 -udp 8888 -name ""Танчики"" -duration 120 -map map2.txt
                ");
        }

        #region UDP

        private static async Task UdpBroadcast(IPAddress serverIp)
        {
            //Создание сырого сокета
            using Socket udpSocket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
            udpSocket.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.Broadcast, true);

            //Создание локальной IP точки и удаленной для получения IP серверов
            IPEndPoint localEndPoint = new IPEndPoint(serverIp, 0);
            EndPoint remoteEndPoint = new IPEndPoint(IPAddress.Broadcast, serverUdpPort);

            //Привязка сокета к локальному IP и инициализация буфера
            udpSocket.Bind(localEndPoint);


            Console.WriteLine("[UDP broadcast] Начало вещания");

            while (true)
            {
                byte[] data = Encoding.UTF8.GetBytes($"{serverName}:{serverTcpPort}:{playersCount}:{winScore}:{mapPath}");
                udpSocket.SendTo(data, remoteEndPoint);

                await Task.Delay(3000);
            }

        }

        #endregion

        #region TCP

        public static async Task StartListener()
        {
            try
            {
                Socket listener = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);

                EndPoint localEndPoint = new IPEndPoint(srcIP, serverTcpPort);

                listener.Bind(localEndPoint);
                listener.Listen(5);

                while (true)
                {
                    Socket client = await listener.AcceptAsync();

                    _ = Task.Run(() => HandleTcpConnection(client));
                }
            }
            catch (Exception ex)
            {
                ShutdownServer($"Порт {serverTcpPort} уже занят другим сервером. Выберите другой.");
            }

        }

        public static async Task HandleTcpConnection(Socket client)
        {
            int? assignedID = null;

            try
            {
                while (true)
                {
                    byte[] typeByte = new byte[1];
                    await client.ReceiveAsync(typeByte, SocketFlags.None);

                    MessageType type = (MessageType)typeByte[0];

                    //Console.WriteLine($"Запрос тип {type}");


                    switch (type)
                    {
                        case MessageType.ConnectionRequest:
                            byte[] header = new byte[2];

                            await client.ReceiveAsync(header, SocketFlags.None);
                            int payloadLen = BitConverter.ToInt16(header, 0);
                            byte[] payload = new byte[payloadLen];

                            await client.ReceiveAsync(payload, SocketFlags.None);

                            string clientName = Encoding.UTF8.GetString(payload);
                            Console.WriteLine($"[Connection Request] Попытка подключения от {clientName}");

                            int clientId = -1;

                            for (int i = 0; i < clients.Length; i++)
                            {
                                if (clients[i] == null)
                                {
                                    clientId = i;
                                    clients[i] = new Client(clientName, clientId, client);
                                    (int, int) spawnPoint = currentMap.GetSpawnPoint(clientId);
                                    tanks[i] = new Tank(clientId, spawnPoint.Item1, spawnPoint.Item2, Directions.Up);
                                    break;
                                }
                            }

                            assignedID = clientId;

                            if (clientId == -1)
                            {
                                Console.WriteLine("[Connection Denied] Отказано в подключении - сервер полон");
                                client.Close();
                                return;
                            }

                            byte[] response = new byte[2];

                            response[0] = (byte)MessageType.ConnectionAccept;

                            response[1] = (byte)clientId;

                            await client.SendAsync(response, SocketFlags.None);
                            Console.WriteLine($"Ответ {clientName} отправлен, выдан ID: {clientId}");

                            playersCount++;


                            break;

                        case MessageType.PlayerInput:

                            byte[] inputHeader = new byte[2];
                            await client.ReceiveAsync(inputHeader, SocketFlags.None);

                            Input input = (Input)inputHeader[0];

                            int inputID = inputHeader[1];


                            Console.WriteLine($"[Input Handler] ID: {inputID}, Input: {input}");


                            //Tank? idTank = tanks.FirstOrDefault<Tank>(t => t.PlayerID == inputID);
                            Tank? idTank = null;

                            for (int i = 0; i < tanks.Length; i++)
                            {
                                if (tanks[i] != null && inputID == tanks[i].PlayerID)
                                {
                                    idTank = tanks[i]; break;
                                }
                            }

                            if (input != Input.NoInput && input != Input.Shoot && idTank.IsAlive)
                            {
                                idTank.Direction = (Directions)input;
                            }

                            if (idTank != null)
                            {
                                switch (input)
                                {
                                    case Input.Up:
                                        idTank.vx = 0;
                                        idTank.vy = -baseSpeed;
                                        break;

                                    case Input.Down:
                                        idTank.vx = 0;
                                        idTank.vy = baseSpeed;
                                        break;

                                    case Input.Right:
                                        idTank.vx = baseSpeed;
                                        idTank.vy = 0;
                                        break;

                                    case Input.Left:
                                        idTank.vx = -baseSpeed;
                                        idTank.vy = 0;
                                        break;

                                    case Input.NoInput:
                                        idTank.vy = 0;
                                        idTank.vx = 0;
                                        break;

                                    case Input.Shoot:

                                        //Console.WriteLine($"interval: {(DateTime.Now - idTank.LastShotTime).TotalMilliseconds}");

                                        if ((DateTime.Now - idTank.LastShotTime).TotalMilliseconds >= idTank.CooldownMs)
                                        {
                                            idTank.LastShotTime = DateTime.Now;
                                            int bulletVx = 0, bulletVy = 0;
                                            int bX = idTank.x, bY = idTank.y;



                                            switch (idTank.Direction)
                                            {
                                                case Directions.Up:
                                                    bulletVx = 0;
                                                    bulletVy = -BulletSpeed;
                                                    bX += idTank.Size / 2 - bulletSize / 2;
                                                    bY += -bulletSize;
                                                    break;
                                                case Directions.Down:
                                                    bulletVx = 0;
                                                    bulletVy = BulletSpeed;
                                                    bX += idTank.Size / 2 - bulletSize / 2;
                                                    bY += idTank.Size;
                                                    break;
                                                case Directions.Left:
                                                    bulletVx = -BulletSpeed;
                                                    bulletVy = 0;
                                                    bY += idTank.Size / 2 - bulletSize / 2;
                                                    bX -= bulletSize;
                                                    break;
                                                case Directions.Right:
                                                    bulletVx = BulletSpeed;
                                                    bulletVy = 0;
                                                    bX += idTank.Size;
                                                    bY += idTank.Size / 2 - bulletSize / 2;
                                                    break;
                                            }

                                            Bullet newBullet = new Bullet(idTank.PlayerID, bulletIdHandler, bX, bY, bulletVx, bulletVy, idTank.Direction);


                                            bulletIdHandler++;

                                            bullets.Add(newBullet);

                                            //Console.WriteLine($"Создана пулька со скоростями: {newBullet.vx}, {newBullet.vy}");

                                        }

                                        break;

                                }
                            }

                            break;

                        case MessageType.ReadyUpdate:
                            byte[] readyData = new byte[2];
                            await client.ReceiveAsync(readyData, SocketFlags.None);

                            int id = readyData[0];
                            bool ready = readyData[1] != 0;

                            Console.WriteLine($"[Rematch Request] Игрок {id} согласен на реванш: {ready}");

                            if (readyStatus.ContainsKey(id))
                            {
                                //Console.WriteLine($"Установлено значение готовности {id} в {ready}");
                                readyStatus[id] = ready;


                                foreach (var k in readyStatus.Keys) Console.WriteLine($"ID : {k} is {readyStatus[k]}");


                                //bool allReady = readyStatus.Values.All(r => r);

                                //if (allReady)
                                //{
                                //    Console.WriteLine("Перезапуск матча");
                                //    RestartMatch();
                                //}
                            }

                            break;

                        case MessageType.Disconnect:

                            byte[] disconnectID = new byte[1];

                            await client.ReceiveAsync(disconnectID, SocketFlags.None);

                            DisconnectClient(disconnectID[0]);
                            Console.WriteLine($"[Client Disconnected] Клиент {disconnectID} отключился.");

                            return;

                            break;
                    }


                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[ERROR] Ошибка работы с клиентом: {ex.Message}");
            }
            finally
            {
                if (assignedID.HasValue)
                {
                    DisconnectClient(assignedID.Value);
                }
                else
                {
                    DisconnectClient(client);
                    //client.Close();
                }
            }

        }

        public static async void DisconnectClient(int id)
        {
            if (clients[id] != null)
            {
                readyStatus.Remove(id);


                Console.WriteLine($"[Client Disconnected] Отключение игрока {clients[id].Name} (ID: {id})");
                try
                {
                    clients[id].ClientSocket.Shutdown(SocketShutdown.Both);
                    clients[id].ClientSocket.Close();
                }
                catch { }

                clients[id] = null;
                tanks[id] = null;
                playersCount--;

                byte[] notification = BuildLeftPacket(id);

                for (int i = 0; i < clients.Length; i++)
                {
                    if (clients[i] == null) continue;
                    try
                    {
                        await clients[i].ClientSocket.SendAsync(notification, SocketFlags.None);

                    }
                    catch
                    {
                        Console.WriteLine("[ERROR] ошибка отправки пакета");
                    }




                }
            }
            if (readyStatus.Keys.Count == 0 && !isMatchActive)
            {
                Console.WriteLine("[Restart Game] Перезапуск матча так как сервер пуст");
                RestartMatch();
            }
        }

        public static async void DisconnectClient(Socket s)
        {
            int id = -1;

            for (int i = 0; i < clients.Length; i++)
            {
                if (clients[i] == null) continue;
                if (clients[i].ClientSocket == s)
                {
                    id = i; break;
                }
            }
            if (id >= 0 && clients[id] != null)
            {
                readyStatus.Remove(id);


                Console.WriteLine($"[Client Disconnected] Отключение игрока {clients[id].Name} (ID: {id}) через поиск по сокету");
                try
                {
                    clients[id].ClientSocket.Shutdown(SocketShutdown.Both);
                    clients[id].ClientSocket.Close();
                }
                catch { }

                clients[id] = null;
                tanks[id] = null;
                playersCount--;

                byte[] notification = BuildLeftPacket(id);

                for (int i = 0; i < clients.Length; i++)
                {
                    if (clients[i] == null) continue;
                    try
                    {
                        await clients[i].ClientSocket.SendAsync(notification, SocketFlags.None);

                    }
                    catch
                    {
                        Console.WriteLine("ошибка отправки пакета");
                    }

                }
            }

            if (readyStatus.Keys.Count == 0 && !isMatchActive)
            {
                Console.WriteLine("[Restart Game] Перезапуск матча так как сервер пуст");
                RestartMatch();
            }
        }

        public static async Task GameLifetimeLoop()
        {
            lastMatchTick = DateTime.Now;

            while (true)
            {
                if (isMatchActive)
                {
                    DateTime now = DateTime.Now;

                    if ((now - lastMatchTick).TotalSeconds >= 1)
                    {
                        if (playersCount > 0) currentMatchTime++;
                        if (currentMatchTime >= matchDuration)
                        {
                            EndMatch();

                        }
                        lastMatchTick = now;
                    }
                    UpdateWorld();

                    await Task.Run(() => BroadcastWorldState());


                    await Task.Delay(30);

                }
                else if (waitingForRematch)
                {
                    bool allReady = readyStatus.Values.All(r => r);

                    if (allReady)
                    {
                        Console.WriteLine("[Restart Game] Перезапуск матча");
                        RestartMatch();

                    }
                    await Task.Delay(200);

                }
                else
                {
                    await Task.Delay(100);
                    Console.WriteLine("Такого быть не должно.");
                }

            }
        }

        public static async Task StartPlayerDataBroadcast()
        {
            while (true)
            {
                await PlayerDataBroadcast();

                await Task.Delay(3000);
            }
        }

        public static async Task PlayerDataBroadcast()
        {
            try
            {
                if (playersCount == 0) return;

                byte[] data = BuildNamePacket();

                //Console.WriteLine($"Начало отправки имен");


                for (int i = 0; i < clients.Length; i++)
                {
                    if (clients[i] == null) continue;

                    await clients[i].ClientSocket.SendAsync(data, SocketFlags.None);
                }
            }
            catch (Exception ex)
            {
                //Console.WriteLine($"Не получилось отправить пакеты имен: {ex.ToString()}");
            }

        }

        public static async Task BroadcastWorldState()
        {
            if (playersCount == 0) return;

            byte[] packet = BuildWorldPacket();

            for (int i = 0; i < clients.Length; i++)
            {
                if (clients[i] == null) continue;
                try
                {
                    await clients[i].ClientSocket.SendAsync(packet, SocketFlags.None);

                }
                catch
                {
                    DisconnectClient(i);
                }
            }

        }




        #endregion

        #region Utils

        public static void UpdateWorld()
        {
            foreach (Tank t in tanks)
            {
                if (t == null) continue;

                if (t.Score >= winScore)
                {
                    EndMatch();
                }

                if (!t.IsAlive && (DateTime.Now - t.DeathTime).TotalMilliseconds > respawnTime)
                {
                    t.IsAlive = true;
                    t.x = t.sx;
                    t.y = t.sy;
                    t.Health = 100;
                }

                if (t.vx == 0 && t.vy == 0) continue;

                int nextX = t.x + t.vx;
                int nextY = t.y + t.vy;

                if (!CheckCollision(nextX, nextY, 40, 40, t.PlayerID) && t.IsAlive)
                {
                    t.x = nextX;
                    t.y = nextY;
                }
                else
                {
                    Console.WriteLine($"[Debug] Коллизия у {t.PlayerID} ({nextX}, {nextY})");
                }


            }

            for (int i = 0; i < bullets.Count; i++)
            {
                Bullet b = bullets[i];
                b.x += b.vx;
                b.y += b.vy;

                CollisionResult res = CheckBulletCollision(b, out Tank hitTank, out int tRow, out int tCol);

                //Console.WriteLine($"Collision {b.selfID} : {res}");

                if (res != CollisionResult.None)
                {
                    if (res == CollisionResult.Tank)
                    {
                        hitTank.Health -= 25;
                        if (hitTank.Health <= 0)
                        {
                            if (hitTank.IsAlive)
                            {
                                tanks[b.OwnerID].Score += 1;
                                hitTank.DeathCount += 1;
                                hitTank.DeathTime = DateTime.Now;
                            }
                            hitTank.IsAlive = false;
                            hitTank.Health = 0;
                            //Console.WriteLine($"Убили {hitTank.PlayerID}: получились очки: {tanks[b.OwnerID].Score}");
                        }
                    }
                    else if (res == CollisionResult.Wall)
                    {
                        //
                    }

                    bullets.RemoveAt(i);
                }


            }
        }
        public static byte[] BuildWorldPacket()
        {

            int activePlayers = 0;

            for (int i = 0; i < clients.Length; i++) if (clients[i] != null) activePlayers++;

            int packetSize = 1 + 2 + 1 + 2 + (activePlayers * 10) + 2 + (bullets.Count * 7);

            int payloadSize = packetSize - (1 + 2);

            byte[] packet = new byte[packetSize];

            packet[0] = (byte)MessageType.WorldState;
            Buffer.BlockCopy(BitConverter.GetBytes((short)payloadSize), 0, packet, 1, 2);

            packet[3] = (byte)activePlayers;
            Buffer.BlockCopy(BitConverter.GetBytes((short)(matchDuration - currentMatchTime)), 0, packet, 4, 2);

            int offset = 6;

            foreach (var tank in tanks)
            {
                if (tank == null) continue;
                packet[offset++] = (byte)tank.Direction;
                Buffer.BlockCopy(BitConverter.GetBytes(tank.IsAlive), 0, packet, offset, 1);
                offset++;
                packet[offset++] = (byte)tank.PlayerID;

                Buffer.BlockCopy(BitConverter.GetBytes((short)tank.x), 0, packet, offset, 2);
                Buffer.BlockCopy(BitConverter.GetBytes((short)tank.y), 0, packet, offset + 2, 2);
                packet[offset + 4] = (byte)tank.Health;

                Buffer.BlockCopy(BitConverter.GetBytes((short)tank.Score), 0, packet, offset + 5, 2);

                offset += 7;
            }

            Buffer.BlockCopy(BitConverter.GetBytes((short)bullets.Count), 0, packet, offset, 2);

            offset += 2;

            foreach (var b in bullets)
            {
                packet[offset++] = (byte)b.Direction;
                packet[offset++] = (byte)b.OwnerID;
                packet[offset++] = (byte)b.selfID;

                Buffer.BlockCopy(BitConverter.GetBytes((short)b.x), 0, packet, offset, 2);
                Buffer.BlockCopy(BitConverter.GetBytes((short)b.y), 0, packet, offset + 2, 2);

                offset += 4;

            }
            return packet;
        }

        public static byte[] BuildNamePacket()
        {
            Dictionary<int, byte[]> names = new Dictionary<int, byte[]>();

            for (int i = 0; i < clients.Length; i++)
            {
                if (clients[i] != null)
                {
                    names[i] = Encoding.UTF8.GetBytes(clients[i].Name);
                }
            }

            int payloadSize = 0;

            foreach (int k in names.Keys)
            {
                payloadSize += 1 + 2 + names[k].Length;
            }

            byte[] packet = new byte[1 + 2 + payloadSize];

            packet[0] = (byte)MessageType.PlayerJoined;
            Buffer.BlockCopy(BitConverter.GetBytes((short)payloadSize), 0, packet, 1, 2);

            int offset = 3;

            foreach (int k in names.Keys)
            {
                packet[offset++] = (byte)k;
                Buffer.BlockCopy(BitConverter.GetBytes((short)(names[k].Length)), 0, packet, offset, 2);
                Buffer.BlockCopy(names[k], 0, packet, offset + 2, names[k].Length);

                offset += 2 + names[k].Length;
            }


            return packet;


        }

        public static byte[] BuildLeftPacket(int id)
        {
            byte[] packet = new byte[2];
            packet[0] = (byte)MessageType.PlayerLeft;
            packet[1] = (byte)id;

            return packet;
        }

        public static byte[] BuildEndGamePacket()
        {
            int active = readyStatus.Count;
            int payloadSize = 1 + active * 5;

            byte[] packet = new byte[1 + 2 + payloadSize];

            packet[0] = (byte)MessageType.MatchResult;
            Buffer.BlockCopy(BitConverter.GetBytes((short)payloadSize), 0, packet, 1, 2);
            packet[3] = (byte)active;

            int offset = 4;

            for (int i = 0; i < clients.Length; i++)
            {
                if (clients[i] != null)
                {
                    packet[offset++] = (byte)clients[i].ID;
                    Buffer.BlockCopy(BitConverter.GetBytes((short)tanks[i]?.Score), 0, packet, offset, 2);
                    Buffer.BlockCopy(BitConverter.GetBytes((short)tanks[i]?.DeathCount), 0, packet, offset + 2, 2);

                    offset += 4;
                }
            }

            return packet;
        }

        public static bool CheckCollision(int targetX, int targetY, int width, int height, int ignoreID = -1)
        {

            int minCol = targetX / GameMap.TileSize;
            int maxCol = (targetX + width - 1) / GameMap.TileSize;

            int minRow = targetY / GameMap.TileSize;
            int maxRow = (targetY + height - 1) / GameMap.TileSize;

            for (int i = minRow; i <= maxRow; i++)
            {
                for (int j = minCol; j <= maxCol; j++)
                {
                    if (currentMap.isSolid(i, j))
                    {
                        return true;
                    }
                }
            }

            foreach (Tank t in tanks)
            {
                if (t == null) continue;
                if (t.PlayerID == ignoreID) continue;

                bool intersectX = targetX < t.x + 40 && targetX + width > t.x;
                bool intersectY = targetY < t.y + 40 && targetY + height > t.y;

                if (intersectX && intersectY)
                {
                    return true;
                }
            }

            return false;
        }

        public static CollisionResult CheckBulletCollision(Bullet b, out Tank hitTank, out int tileRow, out int tileCol)
        {
            hitTank = null;
            tileRow = -1;
            tileCol = -1;

            int minCol = b.x / GameMap.TileSize;
            int maxCol = (b.x + b.Size - 1) / GameMap.TileSize;

            int minRow = b.y / GameMap.TileSize;
            int maxRow = (b.y + b.Size - 1) / GameMap.TileSize;

            for (int i = minRow; i <= maxRow; i++)
            {
                for (int j = minCol; j <= maxCol; j++)
                {
                    if (currentMap.isSolid(i, j))
                    {
                        tileRow = i;
                        tileCol = j;
                        return CollisionResult.Wall;
                    }
                }
            }

            foreach (Tank t in tanks)
            {
                if (t == null) continue;
                if (t.PlayerID == b.OwnerID) continue;

                bool intersectX = b.x < t.x + 40 && b.x + b.Size > t.x;
                bool intersectY = b.y < t.y + 40 && b.y + b.Size > t.y;

                if (intersectX && intersectY)
                {
                    hitTank = t;
                    return CollisionResult.Tank;
                }
            }

            if (b.x < 0 || b.x > 900 || b.y < 0 || b.y > 900) return CollisionResult.Wall;

            return CollisionResult.None;
        }

        public static void EndMatch()
        {
            Console.WriteLine("[Match End] Завершение матча");
            isMatchActive = false;
            waitingForRematch = true;
            readyStatus.Clear();

            for (int i = 0; i < clients.Length; i++)
            {
                if (clients[i] != null)
                {
                    readyStatus[i] = false;
                }
            }

            byte[] resPacket = BuildEndGamePacket();

            for (int i = 0; i < clients.Length; i++)
            {
                if (clients[i] != null)
                {
                    clients[i].ClientSocket.SendAsync(resPacket, SocketFlags.None);
                }
            }


        }

        public static async void RestartMatch()
        {
            waitingForRematch = false;
            isMatchActive = true;

            currentMatchTime = 0;

            lastMatchTick = DateTime.Now;

            for (int i = 0; i < tanks.Length; i++)
            {
                if (tanks[i] != null)
                {
                    var spawn = currentMap.GetSpawnPoint(i);

                    tanks[i].x = spawn.Item1;
                    tanks[i].y = spawn.Item2;
                    tanks[i].sx = tanks[i].x;
                    tanks[i].sy = tanks[i].y;
                    tanks[i].Health = 100;
                    tanks[i].Score = 0;
                    tanks[i].DeathCount = 0;
                    tanks[i].IsAlive = true;
                    tanks[i].vx = 0; tanks[i].vy = 0;
                    tanks[i].LastShotTime = DateTime.MinValue;

                }
            }

            bullets.Clear();
            bulletIdHandler = 0;

            byte[] restPacket = new byte[1];

            restPacket[0] = (byte)MessageType.MatchRestart;

            for (int i = 0; i < clients.Length; i++)
            {
                if (clients[i] != null)
                {
                    await clients[i].ClientSocket.SendAsync(restPacket, SocketFlags.None);
                }
            }


        }

        public static void ShutdownServer(string reason, int exitCode = 1)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine($"\n[КРИТИЧЕСКАЯ ОШИБКА]: {reason}");
            Console.WriteLine("Сервер останавливает работу...");
            Console.ResetColor();
            Console.ReadKey();

            Environment.Exit(exitCode);
        }

        #endregion
    }
}

using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Drawing;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Media;

namespace client
{
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
        Shoot = 5,
    }
    public enum MessageType : byte
    {
       
        ConnectionRequest = 0,  // Клиент -> Сервер: 
        ConnectionAccept = 1,   // Сервер -> Клиент: 
        Disconnect = 2,         // Любой -> Любой: 

        PlayerInput = 3,        // Клиент -> Сервер: 
        WorldState = 4,          // Сервер -> Клиент: 

        PlayerJoined = 5,
        PlayerLeft = 6,

        MatchResult = 7,
        ReadyUpdate = 8,
        MatchRestart = 9
    }

    public class ResultItem
    {
        public int PlayerID { get; set; }
        public string PlayerName { get; set; }
        public int PlayerScore { get; set; }
        public int DeathCount { get; set; }
        public float KD => (DeathCount == 0) ? PlayerScore : (float)PlayerScore / DeathCount;

        public SolidColorBrush ResultColor { get; set; } = Brushes.White;

        public ResultItem(string name, int id, int score, int deaths, SolidColorBrush color)
        {
            PlayerName = name;
            PlayerID = id;
            PlayerScore = score;
            DeathCount = deaths;
            ResultColor = color;
        }
    }
    public class Server : INotifyPropertyChanged
    {
        public int Port { get; set; }
        public string IP { get; set; }
        public int Players { get; set; }
        public string Name { get; set; }

        public int WinScore { get; set; }

        public string MapPath { get; set; }

        public string MapName { get; set; }

        public Server(int _port, string _ip, int _players, string _name, int _winScore, string _mapPath)
        {
            Port = _port;
            IP = _ip;
            Players = _players;
            Name = _name;
            WinScore = _winScore;
            MapPath = _mapPath;

            MapName = MapPath.Split('/')[1].Split('.')[0];
        }

        public override string ToString()
        {
            return $" {Name} | {IP.ToString()} | {Port} | {Players}/4";
        }

        public event PropertyChangedEventHandler PropertyChanged;
        protected void OnPropertyChanged(string name) =>
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
    }
    public class ClientClass
    {
        

        static IPAddress srcIP = IPAddress.Parse("127.0.0.1");
        IPAddress dstIP = null;

        ushort srcPort = 9001;
        ushort dstUdpPort = 8888;

        static List<Server> servers = new List<Server>();

        static string userName = "USER1";
        static int ID;

       
        #region TCP

        public static async Task<(Socket, int)> HandleTcpConnection(Server server, string ip, int tcpPort, string name)
        {
            userName = name;

            Socket socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);

            IPEndPoint localEndPoint = new IPEndPoint(IPAddress.Parse(ip), tcpPort);

            socket.Bind(localEndPoint);


            Console.WriteLine($"Попытка подключения к {server.Name} с IP: {server.IP}  == {server.Port}");
            IPEndPoint serverEndPoint = new IPEndPoint(IPAddress.Parse(server.IP), server.Port);

            try
            {
                socket.Connect(serverEndPoint);

                byte[] connectionRequest = BuildPacket(MessageType.ConnectionRequest);

                await socket.SendAsync(new ArraySegment<byte>(connectionRequest), SocketFlags.None);

                Console.WriteLine("Запрос на подключение к серверу...");

                //Чтение ответа сервера
                byte[] packet = new byte[2];

                await socket.ReceiveAsync(packet, SocketFlags.None);

                MessageType answer = (MessageType)packet[0];


                switch (answer)
                {
                    case MessageType.ConnectionAccept:

                        ID = packet[1];

                        Console.WriteLine($"Успешное подключение, полученный ID: {ID}");

                        break;

                }


            }
            catch (Exception ex)
            {
                Console.WriteLine($"Не удалось подключиться: {ex}");
                socket.Close();
            }

            return (socket, ID);


        }

        public static async Task<(Socket, int)> HandleTcpConnection(Server server, string name)
        {
            userName = name;

            Socket socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);

            Console.WriteLine($"Попытка подключения к {server.Name} с IP: {server.IP}  == {server.Port}");
            IPEndPoint serverEndPoint = new IPEndPoint(IPAddress.Parse(server.IP), server.Port);

            try
            {
                socket.Connect(serverEndPoint);

                byte[] connectionRequest = BuildPacket(MessageType.ConnectionRequest);

                await socket.SendAsync(new ArraySegment<byte>(connectionRequest), SocketFlags.None);

                Console.WriteLine("Запрос на подключение к серверу...");

                //Чтение ответа сервера
                byte[] packet = new byte[2];

                await socket.ReceiveAsync(packet, SocketFlags.None);

                MessageType answer = (MessageType)packet[0];


                switch (answer)
                {
                    case MessageType.ConnectionAccept:

                        ID = packet[1];

                        Console.WriteLine($"Успешное подключение, полученный ID: {ID}");

                        break;

                }


            }
            catch (Exception ex)
            {
                Console.WriteLine($"Не удалось подключиться: {ex}");
                socket.Close();
            }

            return (socket, ID);


        }



        public static byte[] BuildPacket(MessageType type)
        {
            switch (type)
            {
                case MessageType.ConnectionRequest:
                    byte[] nameBytes = Encoding.UTF8.GetBytes(userName);
                    byte[] lenBytes = BitConverter.GetBytes((short)nameBytes.Length);

                    byte[] packet = new byte[1 + 2 + nameBytes.Length];

                    packet[0] = (byte)type;

                    Buffer.BlockCopy(lenBytes, 0, packet, 1, 2);
                    Buffer.BlockCopy(nameBytes, 0, packet, 3, nameBytes.Length);

                    return packet;


                case MessageType.PlayerInput:

                    break;

                default:
                    return [];
            }


            return [];
        }



        #endregion

    }
}

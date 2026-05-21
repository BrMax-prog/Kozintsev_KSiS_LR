using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Net;
using System.Net.Sockets;
using System.Runtime.CompilerServices;
using System.Text;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Navigation;
using System.Windows.Shapes;


namespace client
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    /// 
    
    public partial class MainWindow : Window, INotifyPropertyChanged
    {
        public ObservableCollection<Server> Servers { get; set; } = new ObservableCollection<Server>();

        private Server _selectedServer = null;
        public Server SelectedServer
        {
            get => _selectedServer;
            set { _selectedServer = value; OnPropertyChanged(); OnPropertyChanged(nameof(IsCanConnect)); }
        }

        public string PlayerName { get; set; } = "Игрок";
        public string LocalIP { get; set; } = "127.0.0.1";
        public string LocalPort { get; set; } = "9001";

        public bool customIP {  get; set; } = false;

        public Socket client;
        public int myID;


        public bool IsCanConnect => SelectedServer.IP != null;

        public MainWindow()
        {
            InitializeComponent();
            this.DataContext = this;
            this.Title = "Лобби";

            this.WindowState = WindowState.Maximized;


            StartSearch();

        }

        public MainWindow(string oldName)
        {
            InitializeComponent();
            this.DataContext = this;
            PlayerName = oldName;
            this.Title = "Лобби";
            this.WindowState = WindowState.Maximized;


            StartSearch();
        }


        public void StartSearch()
        {
            CancellationTokenSource _udpSearchToken = new CancellationTokenSource();

            Task.Run(async () =>
            {
                using Socket udpSocket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);

                udpSocket.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);

                //Создание локальной IP точки и удаленной для получения IP серверов
                //IPEndPoint localEndPoint = new IPEndPoint(IPAddress.Parse(LocalIP), 8888);
                IPEndPoint localEndPoint = new IPEndPoint(IPAddress.Any, 8888);

                EndPoint remoteEndPoint = new IPEndPoint(IPAddress.Any, 0);

                //Привязка сокета к локальному IP и инициализация буфера
                udpSocket.Bind(localEndPoint);
                byte[] buffer = new byte[1024];

                //Console.WriteLine("Поиск серверов...");

                while (!_udpSearchToken.IsCancellationRequested)
                {
                    try
                    {
                        SocketReceiveFromResult result = await udpSocket.ReceiveFromAsync(new ArraySegment<byte>(buffer), SocketFlags.None, remoteEndPoint);

                        int recieved = result.ReceivedBytes;

                        EndPoint resultEndPoint = result.RemoteEndPoint;

                        string message = Encoding.UTF8.GetString(buffer, 0, recieved);

                        string[] parts = message.Split(':');

                        string[] ipParts = resultEndPoint.ToString().Split(':');

                        Server existingServer = Servers.FirstOrDefault(s => s.IP == ipParts[0]);

                        string newIP = ipParts[0];
                        string newName = parts[0];
                        int newPort = int.Parse(parts[1]);
                        int newPlayersCount = int.Parse(parts[2]);
                        int winScore = int.Parse(parts[3]);
                        string newMapPath = parts[4];





                        App.Current.Dispatcher.Invoke(() =>
                        {
                            if (existingServer == null)
                            {
                                Server newServer = new Server(newPort, newIP, newPlayersCount, newName, winScore, newMapPath);
                                Servers.Add(newServer);
                            }
                            else
                            {
                                existingServer.Players = int.Parse(parts[2]);
                            }

                            ServersList.Items.Refresh();
                            
                        });
                        
                    }
                    catch (Exception e) { }


                }
            });
        }

        private void CreateServer_Click(object sender, RoutedEventArgs e)
        {
            var win = new CreateServerWindow();
            win.Owner = this;
            bool? result = win.ShowDialog();
            
        }

        private async void Connect_Click(object sender, RoutedEventArgs e)
        {
            if(SelectedServer != null)
            {
                MessageBox.Show($"Подключаемся к {SelectedServer.Name} под именем {PlayerName} c ID: {myID}");

                bool connected = await TryConnectToServer();

                
                if (connected)
                {
                    GameWindow gameWindow = new GameWindow(client, myID, PlayerName, SelectedServer.MapPath);
                    gameWindow.Show();


                    this.Close();
                }
                else
                {
                    MessageBox.Show($"Не подключилось");
                }
            }
            else
            {
                MessageBox.Show($"Сервер не выбран!");
            }
            
            
        }

        private void UserParams_Click(object sender, RoutedEventArgs e)
        {
            customIP = !customIP;

            if (customIP)
            {
                IPInputText.Visibility = Visibility.Visible;
                IPInput.Visibility = Visibility.Visible;
                PortInputText.Visibility = Visibility.Visible;
                PortInput.Visibility = Visibility.Visible;
            }
            else
            {
                IPInputText.Visibility = Visibility.Collapsed;
                IPInput.Visibility = Visibility.Collapsed;
                PortInputText.Visibility = Visibility.Collapsed;
                PortInput.Visibility = Visibility.Collapsed;
            }
        }

        private async Task<bool> TryConnectToServer()
        {
            try
            {
                (Socket, int) tuple;
                if (customIP)
                {
                    tuple = await ClientClass.HandleTcpConnection(SelectedServer, LocalIP, int.Parse(LocalPort), PlayerName);
                }
                else
                {
                    tuple = await ClientClass.HandleTcpConnection(SelectedServer, PlayerName);
                }

                client = tuple.Item1;
                myID = tuple.Item2;
                return true;
            }
            catch (Exception e)
            {
                MessageBox.Show($"Не удалось подключиться:  {e.Message}");
                return false;
            }
        }

        public event PropertyChangedEventHandler PropertyChanged;
        protected void OnPropertyChanged([CallerMemberName] string name = null)
        {
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
        }
    }
}
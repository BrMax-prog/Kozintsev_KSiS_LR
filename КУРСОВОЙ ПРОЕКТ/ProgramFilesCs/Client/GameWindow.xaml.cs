using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.IO;
using System.Linq;
using System.Net.Sockets;
using System.Runtime.CompilerServices;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Shapes;
using static client.GameWindow;

namespace client
{
    /// <summary>
    /// Логика взаимодействия для GameWindow.xaml
    /// </summary>
    public enum TileType : byte
    {
        Empty = 0,
        Wall = 1,
        Bush = 2,
        SteelWall = 3,
    }
public partial class GameWindow : Window
    {
        public Socket client;
        public static int myID;
        public string myName;
        public bool meIsAlive = true;

        private ResultWindow resultWindow;
        

        public class Player : INotifyPropertyChanged
        {
            private int _id;
            public int ID
            {
                get => _id;
                set { _id = value; OnPropertyChanged(); }
            }
            private string _name;
            public string Name
            {
                get => _name;
                set
                {
                    if (_name != value)
                    {
                        _name = value;
                        OnPropertyChanged();
                    }
                }
            }
            public Directions Direction;
            public int X, Y;

            public bool IsAlive = true;

            private int _health;
            public int Health
            {
                get => _health;
                set { _health = value; OnPropertyChanged(); }
            }

            private int _score;
            public int Score
            {
                get => _score;
                set { _score = value; OnPropertyChanged(); }
            }

            public SolidColorBrush ResultColor {  get; set; } = Brushes.White;
            public Rectangle tank { get; set; }

            public Rectangle HealthBar { get; set; }
            public Rectangle HealthBarBg { get; set; }
            public Rectangle ReloadBar = null;
           
            public Brush ColorBrush => ID == myID ? Brushes.LightBlue : Brushes.Red;

            public Player(int _id, string _name, Directions _directions, int _X, int _Y, int _score)
            {
                ID = _id;
                Name = _name;
                Direction = _directions;
                X = _X;
                Y = _Y;
                Score = _score;
            }

            public event PropertyChangedEventHandler PropertyChanged;
            protected void OnPropertyChanged([CallerMemberName] string name = null) =>
                PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));

        }

        public class Bullet
        {
            public int ID;
            public int X;
            public int Y;
            public Directions Direction;

            public Rectangle rect;

            public Bullet(int _id, int _x, int _y, Directions _dir, Rectangle _visual)
            {
                ID = _id;
                X = _x;
                Y = _y;
                Direction = _dir;
                rect = _visual;


                
            }
        }

        public ObservableCollection<Player> players { get; set; } = new ObservableCollection<Player>();
        public Dictionary<int, Bullet> clientBullets= new Dictionary<int, Bullet>();

        public ObservableCollection<ResultItem> resultItems = new ObservableCollection<ResultItem>();

        private Input? lastInput = Input.NoInput;

        public const int TileSize = 40;
        public const int MapSize = 20;

        public int ReloadTime = 2000;
        public DateTime LastShotTime = DateTime.MinValue;


        private Rectangle[,] mapObj = new Rectangle[MapSize, MapSize];
        private CancellationTokenSource ctsReadMessages = new CancellationTokenSource();


        private static ImageBrush myTankBrush;
        private static ImageBrush enemyTankBrush;
        private static ImageBrush bulletBrush;
        private static ImageBrush brickBrush;
        private static ImageBrush steelBrush;
        private static ImageBrush bushBrush;
        private static ImageBrush deadBrush; 

        
       
        public GameWindow(Socket _client, int _id, string _name, string _mapPath)
        {
            client = _client;
            myID = _id;
            myName = _name;
           
            InitializeComponent();
            LoadSprites();
            LoadAndRenderMap(_mapPath);
            PlayersItems.ItemsSource = players;
            this.Title = "Танчики";
            this.WindowState = WindowState.Maximized;

            _ = Task.Run(() => ReadServerMessages(ctsReadMessages.Token), ctsReadMessages.Token);

        }

        public async Task ReadExactlyAsync(byte[] buffer, int size)
        {
            int totalRead = 0;

            while (totalRead < size)
            {
                int read = await client.ReceiveAsync(new ArraySegment<byte>(buffer, totalRead, size - totalRead), SocketFlags.None);

                if (read == 0)
                {
                    throw new SocketException((int)SocketError.ConnectionReset);

                }

                totalRead += read;
            }
        }

        private async Task ReadServerMessages(CancellationToken token)
        {
            try
            {
                while (!token.IsCancellationRequested)
                {
                    byte[] header = new byte[1];

                    await ReadExactlyAsync(header, 1);

                    MessageType type = (MessageType)header[0];

                    int offset = 0;

                    switch (type)
                    {
                        case MessageType.WorldState:


                            byte[] payloadSizeBytes = new byte[2];
                            await ReadExactlyAsync(payloadSizeBytes, 2);

                            int payloadSize = BitConverter.ToInt16(payloadSizeBytes, 0);

                            byte[] payload = new byte[payloadSize];

                            await ReadExactlyAsync(payload, payloadSize);

                            await App.Current.Dispatcher.InvokeAsync(() =>
                            {
                                int playersCount = payload[0];
                                int matchTimeLeft = BitConverter.ToInt16(payload, 1);
                                offset += 3;


                                string remainingMins = (matchTimeLeft / 60).ToString();
                                string remainingSecs = (matchTimeLeft % 60).ToString();
                                if(matchTimeLeft % 60 < 10) remainingSecs = "0" + remainingSecs;

                                RemainingTime.Text = $"{remainingMins} : {remainingSecs}";

                                HashSet<int> activePlayerIds = new HashSet<int>();

                                for (int i = 0; i < playersCount; i++)
                                {

                                    Directions playerDir = (Directions)payload[offset++];
                                    bool isAlive = BitConverter.ToBoolean(payload, offset++);

                                    int currentPlayerID = payload[offset++];
                                    int playerX = BitConverter.ToInt16(payload, offset);
                                    int playerY = BitConverter.ToInt16(payload, offset + 2);
                                    int playerHealth = payload[offset + 4];

                                    int playerScore = BitConverter.ToInt16(payload, offset + 5);

                                    offset += 7;

                                    Player existingPlayer = players.FirstOrDefault(p => p.ID == currentPlayerID);

                                    if (existingPlayer == null)
                                    {

                                        Player newPlayer = new Player(currentPlayerID, "name", playerDir, playerX, playerY, playerScore);
                                        newPlayer.ResultColor = currentPlayerID == myID ? Brushes.Wheat : Brushes.White;

                                        LogBox.Text += $"Добавлен игрок ID: {currentPlayerID}\n";

                                        Color color = currentPlayerID == myID ? Colors.Blue : Colors.Red;
                                        newPlayer.tank = new Rectangle
                                        {
                                            Width = 40,
                                            Height = 40,
                                            Fill = (currentPlayerID == myID) ? myTankBrush : enemyTankBrush,
                                            RenderTransformOrigin = new Point(0.5, 0.5),
                                        };

                                        Canvas.SetLeft(newPlayer.tank, playerX);
                                        Canvas.SetTop(newPlayer.tank, playerY);

                                        GameCanvas.Children.Add(newPlayer.tank);

                                        newPlayer.HealthBar = new Rectangle
                                        {
                                            Width = 40,
                                            Height = 10,
                                            Fill = Brushes.Green

                                        };

                                        newPlayer.HealthBarBg = new Rectangle
                                        {
                                            Width = 40,
                                            Height = 10,
                                            Fill = Brushes.DarkGray
                                        };

                                        Canvas.SetLeft(newPlayer.HealthBar, newPlayer.X);
                                        Canvas.SetTop(newPlayer.HealthBar, newPlayer.Y + 45);
                                        Canvas.SetZIndex(newPlayer.HealthBar, 3);

                                        Canvas.SetLeft(newPlayer.HealthBarBg, newPlayer.X);
                                        Canvas.SetTop(newPlayer.HealthBarBg, newPlayer.Y + 45);
                                        Canvas.SetZIndex(newPlayer.HealthBarBg, 2);

                                        GameCanvas.Children.Add(newPlayer.HealthBar);
                                        GameCanvas.Children.Add(newPlayer.HealthBarBg);

                                        if(currentPlayerID == myID)
                                        {
                                            newPlayer.ReloadBar = new Rectangle
                                            {
                                                Width = 40,
                                                Height = 5,
                                                Fill = Brushes.Wheat,
                                            };

                                            Canvas.SetLeft(newPlayer.ReloadBar, newPlayer.X);
                                            Canvas.SetTop(newPlayer.ReloadBar, newPlayer.Y + 55);
                                            Canvas.SetZIndex(newPlayer.ReloadBar, 3);

                                            GameCanvas.Children.Add(newPlayer.ReloadBar);

                                        }

                                        players.Add(newPlayer);
                                        

                                    }
                                    else
                                    {
                                        if(currentPlayerID == myID) meIsAlive = isAlive;
                                        existingPlayer.IsAlive = isAlive;
                                        
                                        existingPlayer.Direction = playerDir;
                                        
                                        existingPlayer.Health = playerHealth;
                                        existingPlayer.Score = playerScore;
                                        existingPlayer.X = playerX;
                                        existingPlayer.Y = playerY;

                                    }

                                    activePlayerIds.Add(currentPlayerID);
                                }

                                var toRemove = players.Where(p => !activePlayerIds.Contains(p.ID)).ToList();
                                foreach (var p in toRemove)
                                {
                                    App.Current.Dispatcher.Invoke(() =>
                                    {
                                        if (p.tank != null) GameCanvas.Children.Remove(p.tank);
                                        GameCanvas.Children.Remove(p.HealthBar);
                                        GameCanvas.Children.Remove(p.HealthBarBg);
                                        GameCanvas.Children.Remove(p.ReloadBar);
                                        players.Remove(p);
                                    });
                                }

                                int bulletsCount = BitConverter.ToInt16(payload, offset);
                                offset += 2;

                                HashSet<int> activeBullets = new HashSet<int>();

                                try
                                {
                                    for (int i = 0; i < bulletsCount; i++)
                                    {
                                        Directions bulletDir = (Directions)payload[offset++];
                                        
                                        int bulletOwnerID = payload[offset++];
                                        
                                        int bulletSelfID = payload[offset++];

                                        int bulletX = BitConverter.ToInt16(payload, offset);
                                        int bulletY = BitConverter.ToInt16(payload, offset + 2);

                                        offset += 4;

                                        activeBullets.Add(bulletSelfID);

                                        UpdateBullets(bulletSelfID, bulletX, bulletY, bulletDir);

                                    }

                                    var bulletsToRemove = clientBullets.Keys.Where(id => !activeBullets.Contains(id)).ToList();

                                    foreach (var id in bulletsToRemove)
                                    {
                                        if (clientBullets[id].rect != null)
                                        {
                                            GameCanvas.Children.Remove(clientBullets[id].rect);
                                        }

                                        clientBullets.Remove(id);
                                    }
                                }catch(Exception ex)
                                {

                                }

                            });

                            await App.Current.Dispatcher.InvokeAsync(() =>
                            {
                                UpdateCanvas();
                            });

                            break;

                        case MessageType.PlayerLeft:

                            byte[] leftPayload = new byte[1];

                            await ReadExactlyAsync(leftPayload, 1);
                            int disconnectedID = leftPayload[0];

                            Player toRemove = players.FirstOrDefault(p => p.ID == disconnectedID);

                            if (toRemove != null)
                            {
                                await App.Current.Dispatcher.InvokeAsync(() =>
                                {
                                    if (toRemove.tank != null)
                                    {
                                        GameCanvas.Children.Remove(toRemove.tank);
                                    }

                                    GameCanvas.Children.Remove(toRemove.HealthBar);
                                    GameCanvas.Children.Remove(toRemove.HealthBarBg);
                                    GameCanvas.Children.Remove(toRemove.ReloadBar);

                                    LogBox.Text += $"Отключился ( ID: {toRemove.ID} )\n";

                                    players.Remove(toRemove);

                                });
                            }

                            break;

                        case MessageType.PlayerJoined:

                            byte[] namePayloadSizeByte = new byte[2];

                            await ReadExactlyAsync(namePayloadSizeByte, 2);

                            int namePacketSize = BitConverter.ToInt16(namePayloadSizeByte, 0);
                            byte[] nameInfo = new byte[namePacketSize];

                            await ReadExactlyAsync(nameInfo, namePacketSize);

                            offset = 0;

                            while(offset < namePacketSize)
                            {
                                int nameID = nameInfo[offset++];
                                int nameLen = BitConverter.ToInt16(nameInfo, offset);
                                string newName = Encoding.UTF8.GetString(nameInfo, offset + 2, nameLen);

                                offset += 2 + nameLen;

                                await App.Current.Dispatcher.InvokeAsync(() =>
                                {
                                    Player nameChange = players.FirstOrDefault(p => p.ID == nameID);

                                    if(nameChange != null)
                                    {
                                        nameChange.Name = newName;
                                    }
                                });
                            }
                            
                            break;

                        case MessageType.MatchResult:

                            byte[] resultPayloadSize = new byte[2];

                            await ReadExactlyAsync(resultPayloadSize, 2);

                            int resultSize = BitConverter.ToInt16(resultPayloadSize, 0);

                            byte[] results = new byte[resultSize];

                            await ReadExactlyAsync(results, resultSize);

                            int playersCount = results[0];

                            offset = 1;

                            

                            for(int i = 0; i < playersCount; i++)
                            {
                                int resultID = results[offset++];
                                int resultScore = BitConverter.ToInt16(results, offset);
                                int resultDeaths = BitConverter.ToInt16(results, offset + 2);
                                SolidColorBrush resultColor = resultID == myID ? Brushes.Wheat : Brushes.White;

                                string name = players.FirstOrDefault(p => p.ID == resultID).Name;

                                offset += 4;

                                resultItems.Add(new ResultItem(name, resultID, resultScore, resultDeaths, resultColor));


                            }

                            await App.Current.Dispatcher.InvokeAsync(() =>
                            {
                                resultWindow = new ResultWindow(resultItems, myID, client, ctsReadMessages, this, myName);
                                resultWindow.Owner = this;
                                resultWindow.Show();
                            });


                            break;

                        case MessageType.MatchRestart:

                            await App.Current.Dispatcher.InvokeAsync(() =>
                            {
                                if (resultWindow != null)
                                {
                                    resultWindow.CloseWindow();
                                    resultWindow = null;

                                    ResetWorld();
                                }
                            });

                            break;

                    }
                }
            }
            catch(OperationCanceledException)
            {

            }
            catch(Exception ex)
            {
                if (!token.IsCancellationRequested)
                {
                    MessageBox.Show($"Ошибка получения пакетов \n {ex.ToString()}", "Ошибка при чтении сообщения сервера");
                }
            }
            

        }

        private async void Window_KeyDown(object sender, KeyEventArgs e)
        {
            Input? newDir = null;
            bool shot = false;

            switch (e.Key)
            {
                case Key.W:
                case Key.Up:
                    newDir = Input.Up;
                    break;

                case Key.A:
                case Key.Left:
                    newDir = Input.Left;
                    break;

                case Key.S:
                case Key.Down:
                    newDir = Input.Down;
                    break;

                case Key.D:
                case Key.Right:
                    newDir = Input.Right;
                    break;

                case Key.Space:
                    shot = true;
                    break;


            }

            if(newDir != null && newDir != lastInput)
            {
                await SendInputPacket(newDir);
                lastInput = newDir;
            }

            if(shot && (DateTime.Now - LastShotTime).TotalMilliseconds >= ReloadTime && meIsAlive)
            {
                
                await SendInputPacket(Input.Shoot);
                LastShotTime = DateTime.Now;
            }
        }


        private async void Window_KeyUp(object sender, KeyEventArgs e)
        {
            Input? newDir = null;

            switch (e.Key)
            {
                case Key.W:
                case Key.Up:
                case Key.A:
                case Key.Left:
                case Key.S:
                case Key.Down:
                case Key.D:
                case Key.Right:
                    newDir = Input.NoInput;
                    break;

            }

            if (newDir != null)
            {
                await SendInputPacket(newDir);
                lastInput = newDir;
            }

        }

        private async Task SendInputPacket(Input? vec)
        {
            byte[] packet = new byte[3];

            packet[0] = (byte)MessageType.PlayerInput;
            packet[1] = (byte)vec;
            packet[2] = (byte)myID;

            await client.SendAsync(packet, SocketFlags.None);

        }

        private void UpdateCanvas()
        {
            PlayersItems.Items.Refresh();
            foreach(Player p in players)
            {
                if(p.tank != null)
                {
                    double angle = 0;
                    switch (p.Direction)
                    {
                        case Directions.Up: angle = 0; break;
                        case Directions.Right: angle = 90; break;
                        case Directions.Down: angle = 180; break;
                        case Directions.Left: angle = 270; break;
                    }

                    p.tank.RenderTransform = new RotateTransform(angle);

                    Canvas.SetLeft(p.tank, p.X);
                    Canvas.SetTop(p.tank, p.Y);

                    Canvas.SetLeft(p.HealthBar, p.X);
                    Canvas.SetTop(p.HealthBar, p.Y + 45);

                    Canvas.SetLeft(p.HealthBarBg, p.X);
                    Canvas.SetTop(p.HealthBarBg, p.Y + 45);

                    p.HealthBar.Width = (p.Health / 100.0) * 40;

                    if(p.ReloadBar != null)
                    {
                        double cooldown = (DateTime.Now - LastShotTime).TotalMilliseconds;
                        if (cooldown > ReloadTime)
                        {
                            cooldown = ReloadTime;
                            p.ReloadBar.Fill = Brushes.Orange;
                        }
                        else
                        {
                            p.ReloadBar.Fill = Brushes.Wheat;
                        }

                        p.ReloadBar.Width = (cooldown / ReloadTime) * 40;

                        Canvas.SetLeft(p.ReloadBar, p.X);
                        Canvas.SetTop(p.ReloadBar, p.Y + 55);


                        
                    }

                    if (!p.IsAlive)
                    {
                        p.tank.Fill = deadBrush;
                    }
                    else
                    {
                        p.tank.Fill = p.ID == myID ? myTankBrush : enemyTankBrush;
                    }

                }
            }

            foreach(Bullet b in clientBullets.Values)
            {
                Canvas.SetLeft(b.rect, b.X);
                Canvas.SetTop(b.rect, b.Y);
            }

            
        }

        public void UpdateBullets(int id, int x, int y, Directions dir)
        {
            if(clientBullets.ContainsKey(id))
            {
                var bullet = clientBullets[id];
                bullet.X = x;
                bullet.Y = y;
                bullet.Direction = dir;

                Canvas.SetLeft(bullet.rect, x);
                Canvas.SetTop(bullet.rect, y);
            }
            else
            {
                Rectangle visual = new Rectangle
                {
                    Width = 10,
                    Height = 10,
                    Fill = Brushes.White
                };

                Canvas.SetLeft(visual, x);
                Canvas.SetTop(visual, y);

                GameCanvas.Children.Add(visual);

                clientBullets[id] = new Bullet(id, x, y, dir, visual);
                

            }
        }

        public void ResetWorld()
        {
            LogBox.Clear();
            foreach(Player p in players)
            {
                GameCanvas.Children.Remove(p.tank);
                GameCanvas.Children.Remove(p.HealthBar);
                GameCanvas.Children.Remove(p.HealthBarBg);
                GameCanvas.Children.Remove(p.ReloadBar);
            }

            players.Clear();

            foreach(Bullet b in clientBullets.Values)
            {
                GameCanvas.Children.Remove(b.rect);
            }
            clientBullets.Clear();

            resultItems.Clear();
        }
        public void LoadAndRenderMap(string path)
        {
            if (!File.Exists(path)) return;

            string[] lines = File.ReadAllLines(path);

            for(int i = 0; i < MapSize; i++)
            {
                string[] vals = lines[i].Split(' ', StringSplitOptions.RemoveEmptyEntries); 
                for (int j = 0;  j < vals.Length; j++)
                {
                    TileType type = (TileType) byte.Parse(vals[j]);

                    if((byte) type >= 4) type = TileType.Empty;

                    if(type != TileType.Empty)
                    {
                        Rectangle rect = new Rectangle
                        {
                            Width = TileSize,
                            Height = TileSize,
                            Fill = GetTypeBrush(type)
                        };

                        if(type == TileType.Bush)
                        {
                            Canvas.SetZIndex(rect, 10);
                        }
                        else
                        {
                            Canvas.SetZIndex(rect, 0);
                        }

                        Canvas.SetLeft(rect, j * TileSize);
                        Canvas.SetTop(rect, i  * TileSize);

                        GameCanvas.Children.Add(rect);

                        mapObj[i, j] = rect;

                    }
                }
            }
        }

        public Brush GetTypeBrush(TileType type)
        {
            
            switch (type)
            {
                case TileType.Bush: return bushBrush;
                case TileType.Wall: return brickBrush;
                case TileType.SteelWall: return steelBrush;
            }

            return Brushes.Transparent;
        }

        private void LoadSprites()
        {
            if (myTankBrush == null)
            {
                string basePath = System.IO.Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "Sprites");

                var myTankImage = new BitmapImage(new Uri(System.IO.Path.Combine(basePath, "tank_blue.png")));
                myTankBrush = new ImageBrush(myTankImage);

                var enemyTankImage = new BitmapImage(new Uri(System.IO.Path.Combine(basePath, "tank_red.png")));
                enemyTankBrush = new ImageBrush(enemyTankImage);

                var brickImage = new BitmapImage(new Uri(System.IO.Path.Combine(basePath, "brick.png")));
                brickBrush = new ImageBrush(brickImage);

                var steelImage = new BitmapImage(new Uri(System.IO.Path.Combine(basePath, "steel.png")));
                steelBrush = new ImageBrush(steelImage);

                var bushImage = new BitmapImage(new Uri(System.IO.Path.Combine(basePath, "bush.png")));
                bushBrush = new ImageBrush(bushImage);

                var deadImage = new BitmapImage(new Uri(System.IO.Path.Combine(basePath, "tank_dead.png")));
                deadBrush = new ImageBrush(deadImage);

            }
        }
    }
}

using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Net.Sockets;
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
    /// Логика взаимодействия для ResultWindow.xaml
    /// </summary>
    public partial class ResultWindow : Window
    {
        public ObservableCollection<ResultItem> results = new ObservableCollection<ResultItem>();
        public int myID;
        public Socket client;
        public GameWindow owner;
        public CancellationTokenSource ctsReadMessages;
        string myName;
        public ResultWindow(ObservableCollection<ResultItem> _results, int _id, Socket _client, CancellationTokenSource _ctsReadMessages, GameWindow _owner, string _name)
        {
            InitializeComponent();
            results = _results;

            var sortedList = results.OrderByDescending(x => x.KD).ToList();
            results = new ObservableCollection<ResultItem>(sortedList);

            myID = _id;
            client = _client;

            owner = _owner;
            ctsReadMessages = _ctsReadMessages;

            myName = _name;

            ResultsItemsControl.ItemsSource = results;
        }



        public async void ReadyButton_Click(object sender, RoutedEventArgs e)
        {
            ReadyButton.IsEnabled = false;
            LeaveButton.IsEnabled = false;
            ReadyButton.Content = "Ожидаем остальных игроков...";

            byte[] packet = new byte[3];

            packet[0] = (byte)MessageType.ReadyUpdate;

            packet[1] = (byte)myID;
            packet[2] = 1;
            await client.SendAsync(packet);
        }

        public async void LeaveButton_Click(object sender, RoutedEventArgs e)
        {
            byte[] packet = new byte[2];

            packet[0] = (byte)MessageType.Disconnect;
            packet[1] = (byte)myID;

            await client.SendAsync(packet);

            ctsReadMessages.Cancel();

            await Task.Delay(100);

            client.Shutdown(SocketShutdown.Both);
            client.Close();

            
            MainWindow menu = new MainWindow(myName);
            menu.Show();

            this.Close();
            owner.Close();
        }

        public void CloseWindow()
        {
            this.Close();
        }
    }

    
}

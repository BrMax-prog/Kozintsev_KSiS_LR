using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Windows;

namespace client
{
    public partial class CreateServerWindow : Window
    {
        public CreateServerWindow()
        {
            InitializeComponent();
            this.Title = "Создание сервера";
            LoadMaps();
        }

        private void LoadMaps()
        {
            string mapsDir = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "Maps");
            if (!Directory.Exists(mapsDir))
            {
                Directory.CreateDirectory(mapsDir);
                // Можно создать тестовую карту по умолчанию, но не обязательно
            }
            var mapFiles = Directory.GetFiles(mapsDir, "*.txt").Select(Path.GetFileName).ToList();
            if (mapFiles.Count == 0)
                MapComboBox.Items.Add("map1.txt (по умолчанию)");
            else
                foreach (var m in mapFiles)
                    MapComboBox.Items.Add(m);
            MapComboBox.SelectedIndex = 0;
        }

        private void CreateButton_Click(object sender, RoutedEventArgs e)
        {
            // Валидация
            if (string.IsNullOrWhiteSpace(ServerNameBox.Text))
            {
                MessageBox.Show("Введите имя сервера.", "Ошибка", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }
            if (!int.TryParse(DurationBox.Text, out int duration) || duration <= 0)
            {
                MessageBox.Show("Длительность должна быть положительным целым числом.", "Ошибка", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }
            if (!int.TryParse(ScoreTargetBox.Text, out int scoreTarget) || scoreTarget <= 0)
            {
                MessageBox.Show("Цель должна быть положительным целым числом.", "Ошибка", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }
            if (!int.TryParse(TcpPortBox.Text, out int tcpPort) || tcpPort <= 0 || tcpPort > 65535)
            {
                MessageBox.Show("TCP порт должен быть от 1 до 65535.", "Ошибка", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }
            if (!int.TryParse(UdpPortBox.Text, out int udpPort) || udpPort <= 0 || udpPort > 65535)
            {
                MessageBox.Show("UDP порт должен быть от 1 до 65535.", "Ошибка", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }
            string ip = IpBox.Text.Trim().ToLower();
            if (ip != "any" && !System.Net.IPAddress.TryParse(ip, out _))
            {
                MessageBox.Show("IP должен быть 'any' или корректным IP-адресом (например, 192.168.1.100).", "Ошибка", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            // Формируем аргументы командной строки
            string args = $"-name \"{ServerNameBox.Text}\" -duration {duration} -target {scoreTarget} -tcp {tcpPort} -udp {udpPort}";
            if (ip != "any")
                args += $" -ip {ip}";
            
                string selectedMap = MapComboBox.SelectedItem?.ToString();

            if (!string.IsNullOrEmpty(selectedMap) && !selectedMap.Contains("по умолчанию"))
                args += $" -map \"Maps/{selectedMap}\"";

            // Запускаем сервер
            string serverPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "server.exe");
            if (!File.Exists(serverPath))
            {
                MessageBox.Show("Файл server.exe не найден в папке с программой.", "Ошибка", MessageBoxButton.OK, MessageBoxImage.Error);
                return;
            }

            try
            {
                Process.Start(new ProcessStartInfo
                {
                    FileName = serverPath,
                    Arguments = args,
                    UseShellExecute = false,
                    CreateNoWindow = false
                });
                //MessageBox.Show($"Сервер запущен с параметрами:\n{args}", "Успех", MessageBoxButton.OK, MessageBoxImage.Information);
                this.DialogResult = true;
                this.Close();
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Не удалось запустить сервер:\n{ex.Message}", "Ошибка", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void CancelButton_Click(object sender, RoutedEventArgs e)
        {
            this.DialogResult = false;
            this.Close();
        }
    }
}
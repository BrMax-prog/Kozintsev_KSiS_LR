using System;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Threading;

namespace MyTracert
{
    class Program
    {
        //Константы для ICMP
        private const int IcmpEchoRequestType = 8;
        private const int IcmpEchoReplyType = 0;
        private const int IcmpTimeExceededType = 11;

        private const int MaxHops = 40;
        private const int TimeoutMs = 3000;
        private const int PacketsPerHop = 4;

        static void Main(string[] args)
        {
            if (args.Length == 0)
            {
                Console.WriteLine("Использование: mytracert [-r] <IP или Имя узла>");
                Console.WriteLine("  -r : Переводить IP-адреса в имена узлов");
                return;
            }

            bool resolveNames = false;
            string targetHost = "";

            //Парсинг аргументов
            foreach (var arg in args)
            {
                if (arg == "-r") resolveNames = true;
                else targetHost = arg;
            }

            if (string.IsNullOrEmpty(targetHost))
            {
                Console.WriteLine("Не указан целевой узел.");
                return;
            }

            IPAddress targetIp;
            try
            {
                //Попытка перевода доменного имени в IP
                IPAddress[] addresses = Dns.GetHostAddresses(targetHost);
                targetIp = addresses[0];
            }
            catch (Exception)
            {
                Console.WriteLine($"Не удается разрешить системное имя узла {targetHost}.");
                return;
            }

            Console.WriteLine($"Трассировка маршрута к {targetHost} [{targetIp}]");
            Console.WriteLine($"с максимальным числом прыжков {MaxHops}:\n");

            //Сырой сокет для ICMP
            using Socket icmpSocket = new Socket(AddressFamily.InterNetwork, SocketType.Raw, ProtocolType.Icmp);
            icmpSocket.ReceiveTimeout = TimeoutMs;
            icmpSocket.SendTimeout = TimeoutMs;

            ushort sequenceNumber = 1;
            ushort processId = (ushort)Process.GetCurrentProcess().Id;

            bool reachedDestination = false;

            for (int ttl = 1; ttl <= MaxHops && !reachedDestination; ttl++)
            {
                //Установка TTL для текущего прыжка
                icmpSocket.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.IpTimeToLive, ttl);

                Console.Write($"{ttl,3} ");

                IPAddress replyAddress = null;

                for (int i = 0; i < PacketsPerHop; i++)
                {
                    //Создание пакета и обновление sequence number
                    byte[] packet = CreateIcmpEchoRequest(processId, sequenceNumber);
                    sequenceNumber++;


                    EndPoint remoteEndPoint = new IPEndPoint(targetIp, 0);
                    Stopwatch timer = new Stopwatch();

                    try
                    {
                        timer.Start();
                        icmpSocket.SendTo(packet, remoteEndPoint);

                        //Буфер для получения ответа
                        byte[] receiveBuffer = new byte[256];
                        EndPoint replyEndPoint = new IPEndPoint(IPAddress.Any, 0);

                        //Ожидание ответа
                        int bytesRead = icmpSocket.ReceiveFrom(receiveBuffer, ref replyEndPoint);
                        timer.Stop();

                        replyAddress = ((IPEndPoint)replyEndPoint).Address;

                        //Время ответа
                        if (timer.ElapsedMilliseconds == 0)
                            Console.Write("    < 1 мс");
                        else
                            Console.Write($"{timer.ElapsedMilliseconds,5} мс");

                        //Анализ полученного ICMP пакета (пропуск заголовка)
                        int ipHeaderLength = (receiveBuffer[0] & 0x0F) * 4;
                        int icmpType = receiveBuffer[ipHeaderLength];

                        if (icmpType == IcmpEchoReplyType)
                        {
                            reachedDestination = true;
                        }
                    }
                    catch (SocketException)
                    {
                        //Обработка таймаута ожидания
                        Console.Write("\t*   ");
                    }

                    Thread.Sleep(10);
                }

                //Вывод адреса и имени узла
                if (replyAddress != null)
                {
                    string hostNameStr = replyAddress.ToString();
                    if (resolveNames)
                    {
                        try
                        {
                            IPHostEntry hostEntry = Dns.GetHostEntry(replyAddress);
                            hostNameStr = $"{hostEntry.HostName} [{replyAddress}]";
                        }
                        catch { }
                    }
                    Console.Write($"  {hostNameStr}");
                }
                else
                {
                    Console.Write("  Превышен интервал ожидания для запроса.");
                }

                Console.WriteLine();
            }

            Console.WriteLine("\nТрассировка завершена.");
        }

        //Метод для создания массива байтов для ICMP запроса
        private static byte[] CreateIcmpEchoRequest(ushort id, ushort sequence)
        {
            //Заголовок ICMP - 8 байт, полезная нагрузка - 32 байта
            int packetSize = 8 + 32;
            byte[] packet = new byte[packetSize];

            packet[0] = IcmpEchoRequestType; //Type 8 (Echo Request)
            packet[1] = 0;                   //Code 0

            //Checksum - байты 2 и 3

            //Identifier
            byte[] idBytes = BitConverter.GetBytes(id);
            packet[4] = idBytes[0];
            packet[5] = idBytes[1];

            //Sequence Number
            byte[] seqBytes = BitConverter.GetBytes(sequence);
            packet[6] = seqBytes[0];
            packet[7] = seqBytes[1];

            //Заполнение полезной нагрузки
            for (int i = 8; i < packetSize; i++)
            {
                packet[i] = (byte)'a';
            }

            //Контрольная сумма
            ushort checksum = CalculateChecksum(packet);
            byte[] checksumBytes = BitConverter.GetBytes(checksum);
            packet[2] = checksumBytes[0];
            packet[3] = checksumBytes[1];

            return packet;
        }

        //Метод для вычисления контрольной суммы
        private static ushort CalculateChecksum(byte[] buffer)
        {
            int checksum = 0;
            int length = buffer.Length;
            int index = 0;

            while (length > 1)
            {
                checksum += Convert.ToInt32(BitConverter.ToUInt16(buffer, index));
                index += 2;
                length -= 2;
            }

            if (length > 0)
            {
                checksum += Convert.ToInt32(buffer[index]);
            }

            checksum = (checksum >> 16) + (checksum & 0xffff);
            checksum += (checksum >> 16);

            return (ushort)(~checksum);
        }
    }
}
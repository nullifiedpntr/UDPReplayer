using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using PacketDotNet;
using SharpPcap;
using SharpPcap.LibPcap;

internal class Program
{
    private class PacketInfo
    {
        public byte[] Data;

        public bool IsServer;

        public bool IsValid;
    }

    private static List<PacketInfo> _packets = new List<PacketInfo>();

    private static string _clientMacAddress = string.Empty;


    private static void Main(string[] args)
    {
        if (args == null || args.Length <= 1)
        {
            Console.WriteLine(Process.GetCurrentProcess().ProcessName + ".exe <Dump File> <Server Port> [Client MAC Address, only required for PCAP dump file]");
            return;
        }
        if (args.Length == 3)
        {
            _clientMacAddress = args[2].Replace(":", string.Empty).ToUpper();
        }
        string text = args[0];
        if (Path.GetExtension(text) == ".pcap")
        {
            Console.WriteLine("Detected PCAP dump file.");
            if (string.IsNullOrEmpty(_clientMacAddress))
            {
                Console.WriteLine("Client MAC Address is required.");
                return;
            }
            ICaptureDevice val;
            try
            {
                val = new CaptureFileReaderDevice(text);
                val.Open();
            }
            catch (Exception arg)
            {
                Console.WriteLine($"An error occured while opening capture: {arg}");
                return;
            }
            val.OnPacketArrival += new PacketArrivalEventHandler(OnPacketArrival);
            val.Capture();
            val.Close();
        }
        else
        {
            Console.WriteLine("Detected raw (possibly Oodly) dump file, parsing as Oodly anyways.");
            string[] array = File.ReadAllLines(text);
            foreach (string text2 in array)
            {
                string[] array2 = text2.Split(' ');
                _packets.Add(new PacketInfo
                {
                    Data = (byte[])StringToEnumerableByte(array2[1]),
                    IsServer = array2[0].Contains("<="),
                    IsValid = true
                });
            }
        }
        if (_packets.Count > 0)
        {
            Console.WriteLine("Reading capture finished, press any key to start server!");
            Console.ReadKey();
            byte[] array3;
            UdpClient udpClient = new UdpClient(new IPEndPoint(IPAddress.Any, Convert.ToInt32(args[1])));
            IPEndPoint remoteEP = new IPEndPoint(IPAddress.Any, 0);
            Console.WriteLine("Server has started on port " + args[1] + ".");
            while (true)
            {
                array3 = udpClient.Receive(ref remoteEP);
                PushPackets(udpClient, remoteEP);
            }
        } else
        {
            Console.WriteLine("Reading capture failed, packet array does not contain any packets.");
        }
    }

    private static IEnumerable<byte> StringToEnumerableByte(string hex)
    {
        return (from x in Enumerable.Range(0, hex.Length)
                where x % 2 == 0
                select Convert.ToByte(hex.Substring(x, 2), 16)).ToArray();
    }

    private static string EnumerableByteToString(IEnumerable<byte> enumerable)
    {
        StringBuilder stringBuilder = new StringBuilder("byte[] { ");
        foreach (byte item in enumerable)
        {
            stringBuilder.Append($"0x{item:X2}, ");
        }
        stringBuilder.Append("}");
        return stringBuilder.ToString();
    }

    private static void PushPackets(UdpClient server, IPEndPoint sender)
    {
        foreach (var packetInfo in _packets)
        {
            if (!packetInfo.IsServer)
            {
                if (packetInfo.IsValid)
                {
                    server.Send(packetInfo.Data, packetInfo.Data.Length, sender);
                }
            }
        }
    }

    private static byte[] RemoveTrailing(byte[] value)
    {
        int num = value.Length - 1;
        while (value[num] == 0)
        {
            num--;
        }
        byte[] array = new byte[num + 1];
        Array.Copy(value, array, num + 1);
        return array;
    }

    private static void OnPacketArrival(object sender, PacketCapture e)
    {
        Packet val = Packet.ParsePacket(e.GetPacket().LinkLayerType, e.GetPacket().Data);
        EthernetPacket val2 = val.Extract<EthernetPacket>();
        bool isValid = true;
        UdpPacket udpPacket = val.Extract<UdpPacket>();

        if (udpPacket != null && udpPacket.PayloadData != null)
        {
            using (MemoryStream memoryStream = new MemoryStream(e.GetPacket().Data))
            {
                using BinaryReader binaryReader = new BinaryReader(memoryStream);
                memoryStream.Seek(38L, SeekOrigin.Begin);
                byte[] array = binaryReader.ReadBytes(2);
                Array.Reverse(array);
                ushort num = BitConverter.ToUInt16(array, 0);
                if (num != ((Packet)udpPacket).PayloadData.Length + 8)
                {
                    Console.WriteLine($"Packet has failed length check, this packet will be ignored.");
                    Console.WriteLine($"    Expected Length = {num}, Actual Length = {((Packet)udpPacket).PayloadData.Length}");
                    isValid = false;
                }
            }

            _packets.Add(new PacketInfo
            {
                Data = udpPacket.PayloadData,
                IsServer = (val2.SourceHardwareAddress.ToString() != _clientMacAddress.Replace("-", String.Empty).Trim()),
                IsValid = isValid
            });
        }
        else
        {
            Console.WriteLine($"UDP payload or packet missing. Packet Length: {val2.TotalPacketLength}");
        }
    }
}

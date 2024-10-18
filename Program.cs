using System.Net;
using System.Text;

int reserveBits = 16;
bool isBitMask = false;
bool isAsusRuleList = false;


List<string> argsf = new List<string>();

foreach(var a in args)
{
    switch (a)
    {
        case "-m":
            isBitMask = true;
            break;

        case "-asus":
            isAsusRuleList = true;
            break;

        default:
            argsf.Add(a);
            break;
    }

}

if (argsf.Count < 1)
{
    Console.WriteLine("ip2cidr [options] ipadresses_file [reserve_bits=16]");
    Console.WriteLine("\t-m\tprint ip mask");
    Console.WriteLine("\t-asus\tprint for asus internal router list");
    return;
}

string filein = argsf[0];

StreamReader fileIn = new StreamReader(filein/*,new ASCIIEncoding()*/);

if ( argsf.Count > 1)
    reserveBits = int.Parse(argsf[1]);

List<UInt32> ips = new List<UInt32> ();

string? line;
while ((line = fileIn.ReadLine()) != null)
{
    IPAddress ip = IPAddress.Parse(line);
    ips.Add(BitConverter.ToUInt32(ip.GetAddressBytes().Reverse().ToArray()));

}

ips.Sort();

List<CIDR> cidrs = new List<CIDR> ();

int sidx = 0;
for(int idx = 1; idx < ips.Count(); idx++)
{
    uint h1 = ips[idx] >> (32 - reserveBits);
    uint h0 = ips[idx-1] >> (32 - reserveBits);
    if (h0 != h1)
    {
        addCIDR(ips.GetRange(sidx, idx - sidx));
        sidx = idx;
    }
}

if ( sidx < ips.Count() )
    addCIDR(ips.GetRange(sidx, ips.Count() - sidx));


foreach (var item in cidrs)
{
    if ( isAsusRuleList )
    {
        //<108.177.0.0>255.255.0.0>192.168.1.145>>LAN
        Console.Write($"<{item.GetIpAddress()}>{item.GetMask()}>192.168.1.145>>LAN");
    }
    else
        Console.WriteLine(item.ToString(isBitMask));
}


CIDR addCIDR(List<UInt32> gips)
{
    uint start = gips.First();
    uint end = gips.Last();
    uint mask = 0;

    int maskLength = 32;
    while (maskLength > 0)
    {
        mask = uint.MaxValue << (32 - maskLength);
        if ((start & mask) == (end & mask))
            break;
        maskLength--;
    }

    CIDR cidr = new CIDR();
    cidr.ip = start & mask;
    cidr.mask = maskLength;
    cidrs.Add(cidr);
    return cidr;
}


public class CIDR
{
    public UInt32 ip;
    public int mask;

    public IPAddress GetIpAddress()
    {
        byte[] bytes = BitConverter.GetBytes(ip);
        if (BitConverter.IsLittleEndian)
            Array.Reverse(bytes);
        return new IPAddress(bytes);
    }
    public IPAddress GetMask()
    {
       UInt32 m = UInt32.MaxValue << (32 - mask);
       byte[] bytes = BitConverter.GetBytes(m);
        if (BitConverter.IsLittleEndian)
            Array.Reverse(bytes);
        return new IPAddress(bytes);
    }

    public string ToString(bool bmask)
    {
        if ( bmask )
            return $"{GetIpAddress()} {GetMask()}";
        else 
            return $"{GetIpAddress()}/{mask}";
    }
};

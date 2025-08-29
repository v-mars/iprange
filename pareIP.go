package iprange

import (
	"net"
	"strings"
)

// incrementIP 将ip地址增加1
func incrementIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

// conNETLocal 获取当前可以获取的IP网段
func conNETLocal() {
	interfaces, err := net.Interfaces()
	if err != nil {
		return
	}

	for _, i := range interfaces {
		// 跳过虚拟网卡
		if strings.Contains(i.Name, "VirtualBox") || strings.Contains(i.Name, "VMware") {
			continue
		}

		byName, err := net.InterfaceByName(i.Name)
		if err != nil {
			return
		}

		addresses, err := byName.Addrs()
		if err != nil {
			return
		}

		for _, v := range addresses {
			// 检查 IP 地址是否是 CIDR 表示法
			if ipNet, ok := v.(*net.IPNet); ok {
				// 过滤掉 IPv6 地址和 /32 子网
				if ipNet.IP.To4() != nil && ipNet.Mask.String() != "ffffffff" {
					// 获取 IP 地址的第一个字节，用于过滤掉以 169 和 127 开头的 IP 地址
					firstOctet := ipNet.IP.To4()[0]
					if firstOctet != 169 && firstOctet != 127 {
						// 对于每个网络，生成所有可能的 IP 地址
						for ip := ipNet.IP.Mask(ipNet.Mask); ipNet.Contains(ip); incrementIP(ip) {
							//iplist = append(iplist, ip.String())
						}
					}

				}
			}
		}
	}

}

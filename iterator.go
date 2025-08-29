package iprange

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math"
	"math/big"
	"net"
	"strconv"
	"strings"
)

const (
	CidrMode    = iota // CIDR 模式 192.168.0.1/24
	WideMode           // 1.1.1.1-1.1.2.3 宽范围模式
	NarrowMode         // 1-3.1-5.4.1-7 窄范围模式
	NetmaskMode        // 192.168.0.1/255.255.255.0
)

// RangeParseMate Range Info
type RangeParseMate struct {
	s uint8 //start
	e uint8 //end
}

// RangeClassMate IP Range of every byte
type RangeClassMate []RangeParseMate

// Iter Iterator
type Iter struct {
	Mode      int            `json:"mode"`      // 模式
	IsIpv6    bool           `json:"is_ipv6"`   // 是否是ipv6
	IsIpv4    bool           `json:"is_ipv4"`   // 是否是ipv4
	IpStr     string         `json:"ip_str"`    // 填充后的ip字符串
	OriIpStr  string         `json:"ori_ipstr"` // 原始ip字符串
	LastIp    net.IP         `json:"last_ip"`   // ip迭代空间
	Classmate RangeClassMate `json:"classmate"` // ip范围限制信息
	IpNet     *net.IPNet     `json:"ip_net"`    // cidr 模式下的网段信息
	Sip       net.IP         `json:"sip"`       // 开始IP
	Eip       net.IP         `json:"eip"`       // 结束IP
	Network   net.IP         `json:"network"`   // 网络地址
	Broadcast net.IP         `json:"broadcast"` // 广播地址 IPv4有广播地址
	Done      bool           `json:"done"`      // 结束
	TotalNum  uint64         `json:"total_num"` // IP总数	max 64bit(return 0xffffffffffffffff if overflow)
}

// NewIter 创建一个新的IP迭代器，用于遍历指定范围内的所有IP地址
// 支持CIDR、宽范围、窄范围和子网掩码四种模式
//
// 参数:
//
//	ipStr - IP地址字符串，支持以下格式：
//	        1. CIDR格式: "192.168.1.0/24" 或 "2001:db8::/32"
//	        2. 宽范围格式: "192.168.1.1-192.168.1.10" 或 "2001:db8::1-2001:db8::10"
//	        3. 窄范围格式: "192.168.1-2.1-254" 或 "2001:db8::1-2:3-4"
//	        4. 子网掩码格式: "192.168.1.0/255.255.255.0"
//
// 返回值:
//
//	it - IP迭代器指针，可用于遍历IP地址
//	startIp - 起始IP地址
//	err - 错误信息，如果解析失败则返回错误
//
// 使用示例:
//  1. CIDR格式: NewIter("192.168.1.0/30")
//     创建一个包含4个IP地址(192.168.1.0-192.168.1.3)的迭代器
//  2. 宽范围格式: NewIter("192.168.1.10-192.168.1.12")
//     创建一个包含3个IP地址(192.168.1.10-192.168.1.12)的迭代器
//  3. 窄范围格式: NewIter("192.168.1-2.1")
//     创建一个包含2个IP地址(192.168.1.1, 192.168.2.1)的迭代器
//  4. 子网掩码格式: NewIter("192.168.1.0/255.255.255.248")
//     创建一个包含8个IP地址(192.168.1.0-192.168.1.7)的迭代器
func NewIter(ipStr string) (it *Iter, startIp net.IP, err error) {

	it = &Iter{
		Mode:      -1,
		IsIpv6:    false,
		IsIpv4:    false,
		IpStr:     "",
		OriIpStr:  ipStr,
		LastIp:    nil,
		Classmate: nil,
		IpNet:     nil,
		Sip:       nil,
		Eip:       nil,
		Network:   nil,
		Broadcast: nil,
		Done:      false,
		TotalNum:  0,
	}

	// IP判断和填充
	if strings.Contains(ipStr, ".") { // 分段生成IPv4
		it.IsIpv4 = true
	} else if strings.Contains(ipStr, ":") {
		it.IsIpv6 = true
		// 填充缩写

		// :: 扩展
		var fill = func(ipStr string) string {
			buf := strings.Builder{}
			for i := strings.Count(ipStr, ":"); i < 8; i++ {
				buf.WriteString(":0000")
			}
			ipStr = strings.Replace(ipStr, "::", buf.String()+":", 1)
			buf.Reset()
			return ipStr
		}
		if strings.Count(ipStr, "::") == 1 {
			ipStr = fill(ipStr)
		} else if strings.Count(ipStr, "::") == 2 && strings.Count(ipStr, "-") == 1 {
			iL := strings.Split(ipStr, "-")
			iL[0] = fill(iL[0])
			iL[1] = fill(iL[1])
			ipStr = strings.Join(iL, "-")
		}
		// 补零
		ipv6C := strings.Split(ipStr, ":")
		for i, v := range ipv6C {
			ipv6D := strings.Split(v, "-")
			for i2, v2 := range ipv6D {
				for len(v2) < 4 {
					v2 = "0" + v2
				}
				ipv6D[i2] = v2
			}
			ipv6C[i] = strings.Join(ipv6D, "-")
		}
		ipStr = strings.Join(ipv6C, ":")
	}
	it.IpStr = ipStr
	if !it.IsIpv4 && !it.IsIpv6 {
		return nil, nil, fmt.Errorf("not is ip")
	}

	// NetmaskMode - 检查子网掩码格式 (如 192.168.1.0/255.255.255.0)
	if it.Mode == -1 && strings.Contains(ipStr, "/") && strings.Count(ipStr, "/") == 1 {
		parts := strings.Split(ipStr, "/")
		if len(parts) == 2 && strings.Contains(parts[1], ".") {
			// 可能是子网掩码格式
			ip := net.ParseIP(parts[0])
			mask := net.ParseIP(parts[1])
			if ip != nil && mask != nil && ip.To4() != nil && mask.To4() != nil {
				// 创建IPNet
				ipNet := &net.IPNet{
					IP:   ip.Mask(net.IPv4Mask(mask.To4()[0], mask.To4()[1], mask.To4()[2], mask.To4()[3])),
					Mask: net.IPv4Mask(mask.To4()[0], mask.To4()[1], mask.To4()[2], mask.To4()[3]),
				}
				it.Sip = ipNet.IP
				it.IpNet = ipNet
				it.Mode = NetmaskMode

				// 设置网络地址
				it.Network = ipNet.IP

				// 计算并设置广播地址（仅IPv4）
				if ip.To4() != nil {
					// IPv4有广播地址
					broadcast := make(net.IP, len(ipNet.IP))
					copy(broadcast, ipNet.IP)
					for i := range ipNet.Mask {
						broadcast[i] |= ^ipNet.Mask[i]
					}
					it.Broadcast = broadcast
				}
			}
		}
	}

	// CidrMode
	if it.Mode == -1 {
		ip, ipNet, err := net.ParseCIDR(ipStr)
		if err == nil {
			it.Sip = ip.Mask(ipNet.Mask)
			it.IpNet = ipNet
			it.Mode = CidrMode

			// 设置网络地址
			it.Network = ipNet.IP

			// 计算并设置广播地址（仅IPv4）
			if ip.To4() != nil {
				// IPv4有广播地址
				broadcast := make(net.IP, len(ipNet.IP))
				copy(broadcast, ipNet.IP)
				for i := range ipNet.Mask {
					broadcast[i] |= ^ipNet.Mask[i]
				}
				it.Broadcast = broadcast
			}
		}
	}

	// WideMode
	if it.Mode == -1 && strings.Count(ipStr, "-") == 1 {
		startIpStrList := strings.Split(ipStr, "-")
		if len(startIpStrList) == 2 {
			sip := net.ParseIP(startIpStrList[0])
			eip := net.ParseIP(startIpStrList[1])
			if sip == nil || eip == nil || len(sip) != len(eip) {
				err = fmt.Errorf("WideMode parse ip err: %s", ipStr)
			} else {
				it.Mode = WideMode
				it.Sip = sip
				it.Eip = eip
				it.Network = sip
				it.Broadcast = eip
			}
		}
	}

	// NarrowMode
	if it.Mode == -1 {
		var ipClasses []string
		if it.IsIpv4 { // 分段生成IPv4
			ipClasses = strings.Split(ipStr, ".")
		} else if it.IsIpv6 { // 分段生成IPv6
			ipClassesV6 := strings.Split(ipStr, ":")
			if len(ipClassesV6) != 8 {
				err = fmt.Errorf("NarrowMode ipv6 parse err %s", ipStr)
				return
			}
			// 2001::1112-3334
			// to ipClasses
			// 20,01,...,11-33,12-34    (16个)
			for _, v := range ipClassesV6 {
				if len(v) == 4 {
					ipClasses = append(ipClasses, v[:2])
					ipClasses = append(ipClasses, v[2:])
				} else if len(v) == 9 && strings.Contains(v, "-") {
					ipClasses = append(ipClasses, v[:2]+"-"+v[5:7])
					ipClasses = append(ipClasses, v[2:4]+"-"+v[7:])
				}
			}
		}

		// ipClasses to RangeParseMate
		if len(ipClasses) == 4 || len(ipClasses) == 16 {
			for _, v := range ipClasses {
				l0 := strings.Split(v, "-") // range
				var l0s uint64
				if it.IsIpv4 {
					l0s, err = strconv.ParseUint(l0[0], 10, 8)
				} else {
					// ipv6 is hex
					l0s, err = strconv.ParseUint(l0[0], 16, 8)
				}
				l0e := l0s // The default start and end are the same
				if len(l0) > 2 || err != nil {
					return nil, nil, err
				}
				if len(l0) == 2 {
					if it.IsIpv4 {
						l0e, err = strconv.ParseUint(l0[1], 10, 8)
					} else {
						l0e, err = strconv.ParseUint(l0[1], 16, 8)
					}
					if err != nil {
						return nil, nil, err
					}
				}
				it.Classmate = append(it.Classmate, RangeParseMate{
					s: uint8(l0s),
					e: uint8(l0e),
				})
			}
			//
			_startIp := make(net.IP, len(it.Classmate))
			endIp := make(net.IP, len(it.Classmate))
			for i, v := range it.Classmate {
				_startIp[i] = v.s
				endIp[i] = v.e
			}
			it.Mode = NarrowMode
			it.Sip = _startIp
			it.Eip = endIp
			it.Network = _startIp
			it.Broadcast = endIp
		}
	}

	if it.Mode == -1 {
		return nil, nil, fmt.Errorf("unknow mode")
	}

	// Avoid long ipv4 bytes
	if it.Sip.To4() != nil {
		it.Sip = it.Sip.To4()
		it.Eip = it.Eip.To4()

		// fix Fake IPv6, eg:0:0:0:0:0:ffff:aa51:0101
		if it.IsIpv6 && len(it.Classmate) == 16 {
			it.Classmate = it.Classmate[12:]
			it.IsIpv6 = false
			it.IsIpv4 = true
		}
	}
	// dup copy sip to lastIp
	dup := make(net.IP, len(it.Sip))
	copy(dup, it.Sip)
	it.LastIp = dup
	it.TotalNum = it.getTotalNum()
	return it, it.Sip, nil
}

// Next 返回迭代器中的下一个IP地址
// 根据不同的模式(CIDR、宽范围、窄范围、子网掩码)使用不同的方法生成下一个IP地址
// 当没有更多IP地址时，返回nil
//
// 参数:
//
//	it - IP迭代器指针
//
// 返回值:
//
//	net.IP - 下一个IP地址，如果没有更多IP则返回nil
func (it *Iter) Next() net.IP {
	if !it.HasNext() {
		return nil
	}
	switch it.Mode {
	case CidrMode, NetmaskMode: // CIDR模式和子网掩码模式处理方式相同
		inc(it.LastIp)
		if !it.IpNet.Contains(it.LastIp) {
			it.Done = true
			return nil
		}
	case WideMode:
		inc(it.LastIp)
		if bytes.Compare(it.Eip, it.LastIp) < 0 {
			it.Done = true
			return nil
		}
	case NarrowMode:
		classInc(it.LastIp, it.Classmate)
		// 自增后置为初始值，说明到上限了
		if bytes.Compare(it.Sip, it.LastIp) == 0 {
			it.Done = true
			return nil
		}
	default:
		it.Done = true
		return nil
	}

	dup := make(net.IP, len(it.LastIp))
	copy(dup, it.LastIp)
	return dup
}

// HasNext 检查迭代器是否还有下一个IP地址
// 通过检查迭代器的完成状态来判断是否还有未遍历的IP地址
//
// 参数:
//
//	it - IP迭代器指针
//
// 返回值:
//
//	bool - 如果还有下一个IP地址返回true，否则返回false
func (it *Iter) HasNext() bool {
	return !it.Done
}

// GetTotalNum Calculating the Total NUMBER of IP addresses
func (it *Iter) GetTotalNum() uint64 {
	return it.TotalNum
}

func (it *Iter) getTotalNum() uint64 {
	switch it.Mode {
	case CidrMode, NetmaskMode: // CIDR模式和子网掩码模式处理方式相同
		ones, bits := it.IpNet.Mask.Size()
		return uint64(math.Pow(2, float64(bits-ones)))
	case WideMode:
		if it.Eip.To4() != nil {
			return uint64(binary.BigEndian.Uint32(it.Eip.To4()) - binary.BigEndian.Uint32(it.LastIp.To4()) + 1)
		} else {
			ret := big.NewInt(1)
			ret = ret.Add(ret, new(big.Int).Sub(new(big.Int).SetBytes(it.Eip), new(big.Int).SetBytes(it.LastIp)))
			if ret.IsUint64() {
				return ret.Uint64()
			} else {
				return 0xffffffffffffffff
			}
		}
	case NarrowMode:
		var ret = uint64(1)
		for _, v := range it.Classmate {
			ret = ret * (uint64(v.e-v.s) + 1)
		}
		return ret
	}
	return 0
}

// GetIpByIndex ...
func (it *Iter) GetIpByIndex(index uint64) net.IP {
	if index >= it.TotalNum {
		return nil
	}
	it.incByIndex(index)
	return it.LastIp
}

// Contains Check whether the IP address is included
func (it *Iter) Contains(ip net.IP) bool {
	if ip.To4() != nil {
		ip = ip.To4()
	}
	switch it.Mode {
	case CidrMode, NetmaskMode: // CIDR模式和子网掩码模式处理方式相同
		return it.IpNet.Contains(ip)
	case WideMode:
		return bytes.Compare(it.Eip, ip) >= 0 && bytes.Compare(it.Sip, ip) <= 0
	case NarrowMode:
		if len(it.Classmate) != len(ip) {
			return false
		}
		for i, rangeParseMate := range it.Classmate {
			if rangeParseMate.s > ip[i] || rangeParseMate.e < ip[i] {
				return false
			}
		}
		return true
	}
	return false
}

// IP increment by index
func (it *Iter) incByIndex(index uint64) {
	if it.Classmate == nil {
		if it.IsIpv4 {
			it.LastIp = it.LastIp.To4()
			binary.BigEndian.PutUint32(it.LastIp, binary.BigEndian.Uint32(it.Sip.To4())+uint32(index))
		} else {
			ret := new(big.Int).SetBytes(it.Sip)
			ret = ret.Add(ret, new(big.Int).SetUint64(index))
			it.LastIp = ret.Bytes()
		}
	} else {
		length := len(it.Classmate)
		ip := make([]byte, length)
		rangeSpace := make([]uint, length)
		// 每一位的空间容量
		for i, rangeMate := range it.Classmate {
			rangeSpace[i] = uint(rangeMate.e-rangeMate.s) + 1
		}
		// transform 进位除余
		carryBit := uint64(0) // 进位
		var noFirst bool
		for i := length - 1; i >= 0; i-- {
			if rangeSpace[i] == 1 { // 如果空间为1，则不变
				ip[i] = it.Sip[i]
			} else {
				if !noFirst {
					noFirst = true
					carryBit = index
				}
				ip[i] = it.Sip[i] + uint8(carryBit%uint64(rangeSpace[i]))
				carryBit = uint64(uint8(carryBit / uint64(rangeSpace[i])))
			}
		}
		it.LastIp = ip
	}
}

// StartIp ...
func (it *Iter) StartIp() net.IP {
	return it.Sip
}

// EndIp ...
func (it *Iter) EndIp() net.IP {
	return it.Eip
}

// GetNetwork 获取网络地址
func (it *Iter) GetNetwork() net.IP {
	return it.Network
}

// GetBroadcast 获取广播地址
func (it *Iter) GetBroadcast() net.IP {
	return it.Broadcast
}

// GetFormatIp 获得填充的IP字符串
func (it *Iter) GetFormatIp() string {
	return it.IpStr
}

// GetOriIP 获得原始的IP字符串
func (it *Iter) GetOriIP() string {
	return it.OriIpStr
}

// GetStartIpNum 获取开始IP的数字表示
// 对于IPv4返回uint32对应的uint64，对于IPv6返回*big.Int对应的uint64
func (it *Iter) GetStartIpNum() uint64 {
	if it.Sip == nil {
		return 0
	}

	if it.IsIpv4 {
		// IPv4地址使用To4()确保是4字节，然后转换为uint64
		ip4 := it.Sip.To4()
		if ip4 != nil {
			return uint64(binary.BigEndian.Uint32(ip4))
		}
		return 0
	} else {
		// IPv6地址使用big.Int处理
		return new(big.Int).SetBytes(it.Sip.To16()).Uint64()
	}
}

// GetEndIpNum 获取结束IP的数字表示
// 对于IPv4返回uint32对应的uint64，对于IPv6返回*big.Int对应的uint64
func (it *Iter) GetEndIpNum() uint64 {
	if it.Eip != nil {
		if it.IsIpv4 {
			// IPv4地址使用To4()确保是4字节，然后转换为uint64
			ip4 := it.Eip.To4()
			if ip4 != nil {
				return uint64(binary.BigEndian.Uint32(ip4))
			}
			return 0
		} else {
			// IPv6地址使用big.Int处理
			return new(big.Int).SetBytes(it.Eip.To16()).Uint64()
		}
	}

	// 对于CIDR和Netmask模式，计算结束IP
	if it.IpNet != nil {
		if it.IsIpv4 {
			// IPv4 CIDR/Netmask模式的结束IP计算
			ip := make(net.IP, len(it.IpNet.IP))
			copy(ip, it.IpNet.IP)
			// 计算广播地址作为结束IP
			for i := range it.IpNet.Mask {
				ip[i] |= ^it.IpNet.Mask[i]
			}
			ip4 := ip.To4()
			if ip4 != nil {
				return uint64(binary.BigEndian.Uint32(ip4))
			}
			return 0
		} else {
			// IPv6 CIDR模式的结束IP计算
			ones, bits := it.IpNet.Mask.Size()
			// 创建最大的IP地址
			ip := make(net.IP, len(it.IpNet.IP))
			copy(ip, it.IpNet.IP)
			// 设置主机位为1
			for i := ones; i < bits; i++ {
				byteIndex := i / 8
				bitIndex := 7 - (i % 8)
				ip[byteIndex] |= 1 << bitIndex
			}
			return new(big.Int).SetBytes(ip.To16()).Uint64()
		}
	}
	return 0
}

// GetIpList 获得IP列表
func (it *Iter) GetIpList() (outs []net.IP) {
	for nit := it.StartIp(); it.HasNext(); nit = it.Next() {
		outs = append(outs, nit)
	}
	return outs
}

func (it *Iter) GetStrIpList() (outs []string) {
	for nit := it.StartIp(); it.HasNext(); nit = it.Next() {
		outs = append(outs, nit.String())
	}
	return outs
}

// IsIPv4 ...
func (it *Iter) IsIPv4() bool {
	return it.IsIpv4
}

// IsIPv6 ...
func (it *Iter) IsIPv6() bool {
	return !it.IsIpv4
}

// GenIpSet 根据提供的IP字符串生成一组IP地址。
// IP字符串可以表示单个IP、范围或子网。
//
// 参数:
//
//	ipStr - IP地址、范围或子网的字符串表示，支持以下格式：
//	        1. CIDR格式: "192.168.1.0/24"
//	        2. 范围格式: "192.168.1.1-192.168.1.10"
//	        3. 窄范围格式: "192.168.1-2.1-254"
//
// 返回值:
//
//	outs - 包含指定范围内所有IP地址的net.IP切片
//	err - 如果输入字符串无效或处理失败则返回错误
//
// 使用示例:
//  1. CIDR格式: GenIpSet("192.168.1.0/30")
//     返回: [192.168.1.0, 192.168.1.1, 192.168.1.2, 192.168.1.3]
//  2. 范围格式: GenIpSet("192.168.1.1-192.168.1.3")
//     返回: [192.168.1.1, 192.168.1.2, 192.168.1.3]
//  3. 窄范围格式: GenIpSet("192.168.1-2.1")
//     返回: [192.168.1.1, 192.168.2.1]
//
// GenIpSet simple generate a set of ip
func GenIpSet(ipStr string) (outs []net.IP, err error) {
	it, startIp, err := NewIter(ipStr)
	if err != nil {
		return
	}
	for nit := startIp; it.HasNext(); nit = it.Next() {
		outs = append(outs, nit)
	}
	return
}

// IP increment
// inc 将IP地址递增1
// 从IP地址的最后一个字节开始递增，如果发生进位则继续向前递增
// 这是一个底层工具函数，用于IP地址的逐个递增
//
// 参数:
//
//	ip - 需要递增的IP地址
func inc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

// IP Segmented(byte) increment, 有范围的IP自增 1-4.1-4.1-4.1-4 = 1.1.1.1-4.4.4.4
// classInc 按范围限制递增IP地址
// 根据给定的范围信息对IP地址进行递增，确保每个字节都在指定范围内
// 当某个字节达到其范围上限时，会重置为下限值并继续处理前一个字节
//
// 参数:
//
//	ip - 需要递增的IP地址
//	classMate - 每个字节的范围限制信息
func classInc(ip net.IP, classMate RangeClassMate) {
	for j := len(ip) - 1; j >= 0; j-- {
		// 当前分段最大限制
		if ip[j] >= classMate[j].e {
			ip[j] = classMate[j].s // 归初始值
			continue
		}
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

// IpStrToNumber 将IP地址字符串转换为数字表示
// 对于IPv4地址，返回uint32类型的数字
// 对于IPv6地址，返回*big.Int类型的数字
//
// 参数:
//
//	ipStr - 要转换的IP地址字符串
//
// 返回值:
//
//	interface{} - IPv4返回uint32，IPv6返回*big.Int，无效IP返回nil
//
// 使用示例:
//
//	num1 := IpStrToNumber("192.168.1.1") // 返回 uint32(3232235777)
//	num2 := IpStrToNumber("2001:db8::1") // 返回 *big.Int表示的数字
//	num3 := IpStrToNumber("invalid")     // 返回 nil
func IpStrToNumber(ipStr string) uint64 {
	if ipStr == "" {
		return 0
	}

	ip := net.ParseIP(ipStr)
	if ip == nil {
		return 0
	}

	// 如果是IPv4
	if ip.To4() != nil {
		return binary.BigEndian.Uint64(ip.To4())
	}

	// 如果是IPv6
	return new(big.Int).SetBytes(ip.To16()).Uint64()
}

// IpStrToNumberUint64 将IP地址字符串转换为uint64数字表示（仅适用于IPv4）
// 对于IPv6地址或无效IP，返回0
//
// 参数:
//   ipStr - 要转换的IP地址字符串
//
// 返回值:
//   uint64 - IPv4地址对应的数字，IPv6或无效IP返回0
//
// 使用示例:
//   num := IpStrToNumberUint64("192.168.1.1") // 返回 3232235777
//   num2 := IpStrToNumberUint64("2001:db8::1") // 返回 0
func IpStrToNumberUint64(ipStr string) uint64 {
	if ipStr == "" {
		return 0
	}

	ip := net.ParseIP(ipStr)
	if ip == nil {
		return 0
	}

	// 确保是IPv4地址
	ip4 := ip.To4()
	if ip4 == nil {
		return 0
	}
	return uint64(binary.BigEndian.Uint32(ip4))
}

// IpStrToNumberString 将IP地址字符串转换为字符串形式的数字表示
// 对于IPv4和IPv6都适用
//
// 参数:
//
//	ipStr - 要转换的IP地址字符串
//
// 返回值:
//
//	string - IP地址对应的数字字符串，无效IP返回"0"
//
// 使用示例:
//
//	num1 := IpStrToNumberString("192.168.1.1") // 返回 "3232235777"
//	num2 := IpStrToNumberString("2001:db8::1") // 返回大整数的字符串表示
//	num3 := IpStrToNumberString("invalid")     // 返回 "0"
func IpStrToNumberString(ipStr string) string {
	if ipStr == "" {
		return "0"
	}

	ip := net.ParseIP(ipStr)
	if ip == nil {
		return "0"
	}

	// 如果是IPv4
	if ip.To4() != nil {
		return fmt.Sprintf("%d", binary.BigEndian.Uint32(ip.To4()))
	}

	// 如果是IPv6
	num := new(big.Int).SetBytes(ip.To16())
	return num.String()
}

// NumberToIpStr 将数字转换回IP地址字符串
// 支持IPv4的uint32和IPv6的*big.Int
//
// 参数:
//
//	num - 要转换的数字
//	isIPv6 - 是否为IPv6地址
//
// 返回值:
//
//	string - 对应的IP地址字符串，转换失败返回空字符串
//
// 使用示例:
//
//	ip1 := NumberToIpStr(uint32(3232235777), false) // 返回 "192.168.1.1"
//	ip2 := NumberToIpStr(big.NewInt(1234567890), true) // 返回对应的IPv6地址字符串
func NumberToIpStr(num interface{}, isIPv6 bool) string {
	ip := NumberToIp(num, isIPv6)
	if ip == nil {
		return ""
	}
	return ip.String()
}

//====

// IpToNumber 将IP地址转换为数字表示
// 对于IPv4地址，返回uint32类型的数字
// 对于IPv6地址，返回*big.Int类型的数字
//
// 参数:
//
//	ip - 要转换的IP地址
//
// 返回值:
//
//	interface{} - IPv4返回uint32，IPv6返回*big.Int
//
// 使用示例:
//
//	ip1 := net.ParseIP("192.168.1.1")
//	num1 := IpToNumber(ip1) // 返回 uint32(3232235777)
//
//	ip2 := net.ParseIP("2001:db8::1")
//	num2 := IpToNumber(ip2) // 返回 *big.Int表示的数字
func IpToNumber(ip net.IP) interface{} {
	if ip == nil {
		return nil
	}

	// 如果是IPv4
	if ip.To4() != nil {
		return binary.BigEndian.Uint32(ip.To4())
	}

	// 如果是IPv6
	return new(big.Int).SetBytes(ip.To16())
}

// IpToNumberUint64 将IP地址转换为uint64数字表示（仅适用于IPv4）
// 对于IPv6地址，返回0
//
// 参数:
//   ip - 要转换的IP地址
//
// 返回值:
//   uint64 - IPv4地址对应的数字，IPv6返回0
//
// 使用示例:
//   ip := net.ParseIP("192.168.1.1")
//   num := IpToNumberUint64(ip) // 返回 3232235777
func IpToNumberUint64(ip net.IP) uint64 {
	if ip == nil {
		return 0
	}

	// 确保是IPv4地址
	ip4 := ip.To4()
	if ip4 == nil {
		return 0
	}
	return uint64(binary.BigEndian.Uint32(ip4))
}

// IpToNumberString 将IP地址转换为字符串形式的数字表示
// 对于IPv4和IPv6都适用
//
// 参数:
//
//	ip - 要转换的IP地址
//
// 返回值:
//
//	string - IP地址对应的数字字符串
//
// 使用示例:
//
//	ip1 := net.ParseIP("192.168.1.1")
//	num1 := IpToNumberString(ip1) // 返回 "3232235777"
//
//	ip2 := net.ParseIP("2001:db8::1")
//	num2 := IpToNumberString(ip2) // 返回大整数的字符串表示
func IpToNumberString(ip net.IP) string {
	if ip == nil {
		return "0"
	}

	// 如果是IPv4
	if ip.To4() != nil {
		return fmt.Sprintf("%d", binary.BigEndian.Uint32(ip.To4()))
	}

	// 如果是IPv6
	num := new(big.Int).SetBytes(ip.To16())
	return num.String()
}

// NumberToIp 将数字转换回IP地址
// 支持IPv4的uint32和IPv6的*big.Int
//
// 参数:
//
//	num - 要转换的数字
//	isIPv6 - 是否为IPv6地址
//
// 返回值:
//
//	net.IP - 对应的IP地址
//
// 使用示例:
//
//	ip1 := NumberToIp(uint32(3232235777), false) // 返回 192.168.1.1
//	ip2 := NumberToIp(big.NewInt(1234567890), true) // 返回对应的IPv6地址
func NumberToIp(num interface{}, isIPv6 bool) net.IP {
	if isIPv6 {
		if bigInt, ok := num.(*big.Int); ok {
			bytes := bigInt.Bytes()
			// 确保是16字节的IPv6地址
			ip := make(net.IP, 16)
			copy(ip[16-len(bytes):], bytes)
			return ip
		}
		return nil
	} else {
		var n uint32
		switch v := num.(type) {
		case uint32:
			n = v
		case uint64:
			n = uint32(v)
		case int:
			n = uint32(v)
		case int64:
			n = uint32(v)
		default:
			return nil
		}
		ip := make(net.IP, 4)
		binary.BigEndian.PutUint32(ip, n)
		return ip
	}
}

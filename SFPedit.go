package main

import (
	"crypto/md5"
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"hash/crc32"
	"io/ioutil"
	"os"
	"reflect"
	"strings"
)

const (
	NOTSUPPORTED_IND = 0
	FINISAR_IND      = 1
	METHODE_IND      = 2

	FINISAR_IDENT_STRING = "finisar"
	METHODE_IDENT_STRING = "methode"
)

func sffcmpl(hb byte) (dt string) {
	switch hb {
	case 00:
		return "Digital diagnostic functionality not included or undefined."
	case 01:
		return "Includes functionality described in Rev 9.3 SFF-8472"
	case 02:
		return "Includes functionality described in Rev 9.5SFF-8472."
	case 03:
		return "Includes functionality described in Rev 10.2SFF-8472."
	case 04:
		return "Includes functionality described in Rev 10.4SFF-8472."
	case 05:
		return "Includes functionality described in Rev 11.0SFF-8472."
	default:
		return "TBD"
	}
}

func diagnosticmonitortype_detail(hb byte) (dt string) {
	rstring := ""
	if hb&0x04 != 0 {
		rstring += "Address change required see section above.\r\n"
	}
	if hb&0x08 != 0 {
		rstring += "Received power measurement type: Average Power\r\n"
	} else {
		rstring += "Received power measurement type: OMA\r\n"
	}
	if hb&0x10 != 0 {
		rstring += "Externally Calibrated\r\n"
	}
	if hb&0x20 != 0 {
		rstring += "Internally Calibrated\r\n"
	}
	if hb&0x40 != 0 {
		rstring += "Digital diagnostic monitoring implemented SFF-8472"
	}

	return rstring
}

func main() {
	var InFile string
	var serial string
	var MakeFileFlag bool
	var RepairFlag bool

	OutFileName := ""

	//Finisar Salt
	var key []byte
	FinisarSalt := []byte{0x8D, 0xDA, 0xE6, 0xA4, 0x6E, 0xC9, 0xDE, 0xF6, 0x10, 0x0B, 0xF1, 0x85, 0x05, 0x9C, 0x3D, 0xAB}
	MethodeSalt := []byte{0x4A, 0xF8, 0x67, 0x16, 0xED, 0x1E, 0x2F, 0x34, 0x7C, 0xA1, 0x3C, 0x99, 0x78, 0xAD, 0x8C, 0xA0}
	sn := []byte{0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20}

	flag.StringVar(&InFile, "in", "", "please, provide input filename")
	flag.StringVar(&serial, "sn", "", "please, provide serival number")
	flag.BoolVar(&RepairFlag, "r", false, "flag for repair dump, make file with 'rep' suffix or file with name provide by -mf flag")
	flag.BoolVar(&MakeFileFlag, "mf", false, "Make file: if You want to generate output file, please provide this flag")

	flag.Parse()

	if len(InFile) < 2 {
		fmt.Println("Need input filename")
		os.Exit(1)
	}
	if MakeFileFlag {
		if !RepairFlag {
			if len(serial) < 2 {
				fmt.Println("Need serial number")
				os.Exit(1)
			} else {
				OutFileName = "out" + serial + ".bin"
			}
		}
	} else {
		if RepairFlag {
			ModfInFile := strings.Replace(InFile, ".bin", "", 1)
			OutFileName = fmt.Sprintf("%s_%s.bin", ModfInFile, "rep")
		}
	}

	var md5_src_str []byte
	md5_src_str = make([]byte, 49)

	mbuf, err := ioutil.ReadFile(InFile)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	//Данные файла
	wavelength := binary.BigEndian.Uint16(mbuf[60:62])
	lengthkmSM := int(mbuf[14])
	length100mSM := int(mbuf[15])
	wavelengthStr := fmt.Sprintf("Wavelength: %d", wavelength)
	rangeF := fmt.Sprintf("Link length supported for 9/125 μm fiber, units of km: %d", lengthkmSM)
	rangeF100m := fmt.Sprintf("Link length supported for 9/125 μm fiber, units of 100 m: %d", length100mSM)

	tbuf := make([]byte, 1)
	tbuf[0] = mbuf[92]
	DiagnosticType := hex.EncodeToString(tbuf)

	VendorName := string(mbuf[20:36])
	VendorPartNum := string(mbuf[40:56])
	VendorOUI := hex.EncodeToString(mbuf[37:40])
	ReadedCRC := mbuf[124:128]
	SerialNumberFacts := ""
	if MakeFileFlag {
		SerialNumberFacts = string(sn)
	} else {
		SerialNumberFacts = string(mbuf[68:84])
	}

	factbuftocrc32 := mbuf[96 : 96+28]

	factcrc32ch := crc32.ChecksumIEEE(factbuftocrc32)
	factcrc32buf := make([]byte, 4)
	binary.LittleEndian.PutUint32(factcrc32buf, factcrc32ch)

	fmt.Println("Serial is:", SerialNumberFacts)
	fmt.Println("Vendor name:", VendorName)
	fmt.Println("Vendor OUI:", VendorOUI)
	fmt.Println("Vendor Part Number:", VendorPartNum)
	fmt.Println("Diagnostic Monitoring Type HEX:", DiagnosticType)

	fmt.Println("=== SFF 8472 data ===================================")
	fmt.Println(diagnosticmonitortype_detail(mbuf[92]))
	fmt.Println(sffcmpl(mbuf[94]))
	fmt.Println("=====================================================")

	fmt.Println(wavelengthStr)
	fmt.Println(rangeF)
	fmt.Println(rangeF100m)

	fmt.Println("Calculated CRC:", hex.EncodeToString(factcrc32buf))
	fmt.Println("Readed CRC:", hex.EncodeToString(ReadedCRC))
	if !reflect.DeepEqual(factcrc32buf, ReadedCRC) {
		fmt.Println("ERROR! Wrong CRC in input file")
	}
	Ven := strings.ToLower(strings.TrimSpace(VendorName))
	VenInd := NOTSUPPORTED_IND
	if strings.Contains(Ven, FINISAR_IDENT_STRING) {
		VenInd = FINISAR_IND
	}
	if strings.Contains(Ven, METHODE_IDENT_STRING) {
		VenInd = METHODE_IND
	}

	switch VenInd {
	case FINISAR_IND:
		key = FinisarSalt
		fmt.Println("Will be use Finisar salt")
		break
	case METHODE_IND:
		key = MethodeSalt
		fmt.Println("Will be use Method salt")
		break
	default:
		key = FinisarSalt
		fmt.Println("Vendor not supported, will be use Finisar salt")
	}

	if RepairFlag {
		serial = SerialNumberFacts
		MakeFileFlag = true
	}

	bsnfc := []byte(serial)
	if len(bsnfc) > 16 {
		bsnfc = bsnfc[:16]
	}
	if len(bsnfc) < 16 {
		copy(sn[:len(bsnfc)], bsnfc)
		bsnfc = sn
	}

	if MakeFileFlag {
		//Cechsum base
		cc_base := 0
		for a := 0; a < 63; a++ {
			cc_base += int(mbuf[a])
		}

		cc_base_byte := byte(cc_base)
		mbuf[63] = cc_base_byte

		//Checksumm
		sum22 := 0
		copy(mbuf[68:68+16], bsnfc)
		for a := 64; a < 95; a++ {
			sum22 += int(mbuf[a])
		}
		mbuf[95] = byte(sum22)

		//Make MD5 with salt data (Finisar)
		md5_src_str[0] = mbuf[98]
		copy(md5_src_str[1:1+16], mbuf[20:20+16])
		copy(md5_src_str[17:17+16], mbuf[68:68+16])
		copy(md5_src_str[17:17+16], mbuf[68:68+16])
		copy(md5_src_str[33:], key[:])
		hashbytes := md5.Sum(md5_src_str)
		copy(mbuf[99:99+16], hashbytes[:])

		buftocrc32 := mbuf[96 : 96+28]

		crc32ch := crc32.ChecksumIEEE(buftocrc32)
		crc32buf := make([]byte, 4)
		binary.LittleEndian.PutUint32(crc32buf, crc32ch)

		copy(mbuf[124:124+4], crc32buf[:])
		fmt.Println("Write file:", OutFileName)
		ioutil.WriteFile(OutFileName, mbuf, 0644)
	}
}

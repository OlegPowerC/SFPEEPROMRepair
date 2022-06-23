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
	NOTSUPPORTED_IND = 0x00
	FINISAR_IND      = 0x02
	METHODE_IND      = 0x0E

	FINISAR_IDENT_STRING = "finisar"
	METHODE_IDENT_STRING = "methode"
)

/*
type SPDData struct {
	//Name				type		offsett in byffer
	MdIdent				byte		//00
	MdExtIdent			byte		//01
	MdConnector			byte		//02
	MdTransceiver		[8]byte		//03-10
	MdEncoding			byte		//11
	MdSignalingRate		byte		//12
	MdRateIdent			byte		//13
	MdLengthSMFKm		byte		//14
	MdLengthSMF100m		byte		//15
	MdLengthMMFOM210m	byte		//16
	MdLengthMMFOM110m	byte		//17
	MdLengthMMFOM410m	byte		//18
	MdLengthMMFOM310m	byte		//19
	MdVendorName		[16]byte	//20-35
	MdTransceiver2		byte		//36
	MdVendorOUI			[3]byte		//37-39
	MdVendorPN			[16]byte	//40-55
	MdVendorRev			[4]byte		//56-59
	MdWavelength		[2]byte		//60-61
	MdFCSpeed			byte		//62
	mdCC_BASE			byte		//63

	MdOption			[2]byte		//64-65
	MdSignalRateMax		byte		//66
	MdSignalRateMin		byte		//67
	MdVendorSN			[16]byte	//68-83
	MdDateCode			[8]byte		//84-91
	MdDiagType			byte		//92
	MdEnhOptions		byte		//93
	MdSFF8472Complaince	byte		//94
	MdCC_EXT			byte		//95

	MdVSVendorID		byte		//98

}
*/

/*
func FillMDData(buffer []byte)(err error,MdData SPDData){
	if len(buffer) < 128 {
		return fmt.Errorf("Too short buffer:%d bytes",len(buffer)),nil
	}
	MdData.MdIdent
}

*/

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

func ComputeHash(VenId byte, VendorName []byte, SerialNumber []byte, VendorKey []byte) (Err error, Hash [16]byte) {
	//Считаем MD5 от строки из:
	//Идентификатор производителя, адрес 0x62(98)	- 1 байт
	//Имя производителя, адрес 0x14(20)-0x23(35)	- 16 байт
	//Серийный номер, адрес 0x44(68)-0x53(83)		- 16 байт
	if len(VendorName) != 16 || len(SerialNumber) != 16 || len(VendorKey) != 16 {
		return fmt.Errorf("Error in arguments length"), Hash
	}
	var md5_src_str []byte
	md5_src_str = make([]byte, 49)

	md5_src_str[0] = VenId
	copy(md5_src_str[1:1+16], VendorName[:])
	copy(md5_src_str[17:17+16], SerialNumber[:])
	copy(md5_src_str[33:], VendorKey[:])
	return nil, md5.Sum(md5_src_str)
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

	//Идентификатор производителя - адрес 0x62. Извесные нам: 0x02 - Finisar, 0x0E - Methode
	Ven := uint(mbuf[0x62])

	switch Ven {
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
		fmt.Println("Vendor not supported by this software, will be use Finisar salt")
	}

	//Make MD5 with salt
	_, hashbytes := ComputeHash(mbuf[98], mbuf[20:20+16], mbuf[68:68+16], key)
	fmt.Println("Calculated hash:", hex.EncodeToString(hashbytes[:]))
	fmt.Println("Readed hash", hex.EncodeToString(mbuf[99:99+16]))
	if !reflect.DeepEqual(hashbytes[:], mbuf[99:99+16]) {
		fmt.Println("ERROR! Wrong hash in input file")
	}

	//Checksum base
	cc_base := 0
	for a := 0; a < 63; a++ {
		cc_base += int(mbuf[a])
	}
	cc_base_byte := byte(cc_base)
	fmt.Println("CC_Base calculated:", hex.EncodeToString([]byte{cc_base_byte}))
	fmt.Println("CC_Base readed:", string(hex.EncodeToString([]byte{mbuf[63]})))
	if cc_base_byte != mbuf[63] {
		fmt.Println("ERROR! Wrong CC_Base in input file")
	}
	mbuf[63] = cc_base_byte

	//Checksum
	CC_ext_calculated := 0
	for a := 64; a < 95; a++ {
		CC_ext_calculated += int(mbuf[a])
	}
	CC_ext_readed := int(mbuf[95])
	fmt.Println("CC_Ext calculated:", hex.EncodeToString([]byte{byte(CC_ext_calculated)}))
	fmt.Println("CC_Ext readed:", string(hex.EncodeToString([]byte{byte(CC_ext_readed)})))
	if byte(CC_ext_calculated) != byte(CC_ext_readed) {
		fmt.Println("ERROR! Wrong CC_Ext in input file")
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

		//Checksum
		sum22 := 0
		copy(mbuf[68:68+16], bsnfc)
		for a := 64; a < 95; a++ {
			sum22 += int(mbuf[a])
		}
		mbuf[95] = byte(sum22)

		//Make MD5 with salt
		_, hashbytesafterfillbuffer := ComputeHash(mbuf[98], mbuf[20:20+16], mbuf[68:68+16], key)
		copy(mbuf[99:99+16], hashbytesafterfillbuffer[:])

		buftocrc32 := mbuf[96 : 96+28]
		crc32ch := crc32.ChecksumIEEE(buftocrc32)
		crc32buf := make([]byte, 4)
		binary.LittleEndian.PutUint32(crc32buf, crc32ch)
		copy(mbuf[124:124+4], crc32buf[:])
		fmt.Println("Write file:", OutFileName)
		ioutil.WriteFile(OutFileName, mbuf, 0644)
	}
}

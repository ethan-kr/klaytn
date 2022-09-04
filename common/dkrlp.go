package common
//package main

import (
	"errors"
	//"bytes"
	//"encoding/hex"
	//"fmt"
)

type rlpDS struct {
	kind	uint8
	data	[]byte
	length	int
} 

/*
func main() {
	srcStr, answer := []byte("f8729e20fb89cf6444214fbeec19fa56fb55644b3d95cd60b2db025a0a9a3d0bcfb85101f84e02808005f848a302a10241648c5a079203f35708ba25630dee558dcffd6cc0a03d2d8903c595455154b8a302a102748fe1aa2f0670f02a82934c2e0fbe691455a845fcdbf053ffa14b38a8f93a9f"), []byte("f8729e20fb89cf6444214fbeec19fa56fb55644b3d95cd60b2db025a0a9a3d0bcfb85101f84e02808005f848a302a10241648c5a079203f35708ba25630dee558dcffd6cc0a03d2d8903c595455154b8a302a102748fe1aa2f0670f02a82934c2e0fbe691455a845fcdbf053ffa14b38a8f93a9f")
	//srcStr, answer := []byte("f90291a8d9a477f37ba89eb6c1eade5b4651a350a52c85ce1b13950c72814835f2e224cd5a428d00ffff7e00a8b62f6dd259b585a05b0e8cced950a73b40e1c854221bf3e0d29ba570af2db4db47428d00ffff0900a87c3175499c2891c0e7fe4cecb21d8fd685d33989d3e88bf9748a264145e87d1c5a428d00ffff7600a8b4e7e9191115be7ef34308cea35358d63dda7be9703ccf312357e6f2bdaa824835428d00ffff0c00a89c23aedd03f154bda5e82b8ffd382b899388036475202bab3ed70caf343c47cd59428d00ffff2b00a85155de8db110cb40758469d2529eac6a785f3c73cdac5d89a0654c8f2484a18f5a428d00ffff9000a890070a56b3613e0e1ee0234857e37fa455d49594bd119a7f3a4e0569ff93120e5a428d00ffff8900a8b52558d2bbd0ef6e301714ad9fd6dcb5ef16e0afb88333d79790c6caec254ce9cb418d00ffff1800a86a8d95602b2b6b0f1dc23729a59fe8a187b559f3bcbc7dff19e596837e04493655428d00ffff4b00a84c71ef307935aaed599f115885fa0cf05da1038b3c7e00ae54019d519386e50c55428d00ffff5100a8b237383914a1dd1ba53a412b0d0c4b4d09113f8d1c96c510ce297b19e29ad9fe5a428d00ffff8700a8d79e70400a6225aa5c8ac163474e4ccc76aa1036319ef6463b89ec8314bd897457428d00ffff0c00a86490f0eaff2f1563bc47c249d8facbf6ab45aeb41a1f4577f1dd33c88e809cce5a428d00ffff8e00a8ec60f7e9659bef8da0432b7ef2f48574b96d9fb377903dad7de224815cc269fe5a428d00ffff8c00a8f53f6e7545ed157b4e32b501e23ee514c8d4e4d3725cc8e1f77cd7220d01f11259428d00ffff2e00a88ce0f8aa18d33e1ccd30c9cc8e2d5b90524cd25ee6c40bd2726c1aeb9e82018452428d00ffff090080"), []byte("f90211a0d9a477f37ba89eb6c1eade5b4651a350a52c85ce1b13950c72814835f2e224cda0b62f6dd259b585a05b0e8cced950a73b40e1c854221bf3e0d29ba570af2db4dba07c3175499c2891c0e7fe4cecb21d8fd685d33989d3e88bf9748a264145e87d1ca0b4e7e9191115be7ef34308cea35358d63dda7be9703ccf312357e6f2bdaa8248a09c23aedd03f154bda5e82b8ffd382b899388036475202bab3ed70caf343c47cda05155de8db110cb40758469d2529eac6a785f3c73cdac5d89a0654c8f2484a18fa090070a56b3613e0e1ee0234857e37fa455d49594bd119a7f3a4e0569ff93120ea0b52558d2bbd0ef6e301714ad9fd6dcb5ef16e0afb88333d79790c6caec254ce9a06a8d95602b2b6b0f1dc23729a59fe8a187b559f3bcbc7dff19e596837e044936a04c71ef307935aaed599f115885fa0cf05da1038b3c7e00ae54019d519386e50ca0b237383914a1dd1ba53a412b0d0c4b4d09113f8d1c96c510ce297b19e29ad9fea0d79e70400a6225aa5c8ac163474e4ccc76aa1036319ef6463b89ec8314bd8974a06490f0eaff2f1563bc47c249d8facbf6ab45aeb41a1f4577f1dd33c88e809ccea0ec60f7e9659bef8da0432b7ef2f48574b96d9fb377903dad7de224815cc269fea0f53f6e7545ed157b4e32b501e23ee514c8d4e4d3725cc8e1f77cd7220d01f112a08ce0f8aa18d33e1ccd30c9cc8e2d5b90524cd25ee6c40bd2726c1aeb9e82018480")
	//srcStr, answer := []byte("f8729e3aa21f22bb1d06ffd3052056f424f5a75c897909bf19054f5c5faef94ba4b85101f84e02808005f848a302a10284d9016c570bd864eaa2621c482acf9a8109a8bbd315369029b6433a6d591a6fa302a102748fe1aa2f0670f02a82934c2e0fbe691455a845fcdbf053ffa14b38a8f93a9f"), []byte("f8729e3aa21f22bb1d06ffd3052056f424f5a75c897909bf19054f5c5faef94ba4b85101f84e02808005f848a302a10284d9016c570bd864eaa2621c482acf9a8109a8bbd315369029b6433a6d591a6fa302a102748fe1aa2f0670f02a82934c2e0fbe691455a845fcdbf053ffa14b38a8f93a9f")
	//srcStr, answer := []byte("f8729e379923746b521cba3a25830d3c5c7c4eca96f39c4eb50d055302c6adc5bbb85101f84e02808005f848a302a1021bf80c2bb3766fe0ad90dd3838a6d37fc4e8d99ee5ca2756daf0c8a1a02ea7c7a302a102748fe1aa2f0670f02a82934c2e0fbe691455a845fcdbf053ffa14b38a8f93a9f"), []byte("f8729e379923746b521cba3a25830d3c5c7c4eca96f39c4eb50d055302c6adc5bbb85101f84e02808005f848a302a1021bf80c2bb3766fe0ad90dd3838a6d37fc4e8d99ee5ca2756daf0c8a1a02ea7c7a302a102748fe1aa2f0670f02a82934c2e0fbe691455a845fcdbf053ffa14b38a8f93a9f")
	//srcStr, answer := []byte("f8729e207ed723a0db1f98bfdf6ad39825aad0f8411ec118542883c9ca7b2b9f41b85101f84e02808005f848a302a103c73a7767c4294627455a4ad454fd5b0ec5cf4dbf9db0c1bd4ae3895ae754e3a8a302a102748fe1aa2f0670f02a82934c2e0fbe691455a845fcdbf053ffa14b38a8f93a9f"), []byte("f8729e207ed723a0db1f98bfdf6ad39825aad0f8411ec118542883c9ca7b2b9f41b85101f84e02808005f848a302a103c73a7767c4294627455a4ad454fd5b0ec5cf4dbf9db0c1bd4ae3895ae754e3a8a302a102748fe1aa2f0670f02a82934c2e0fbe691455a845fcdbf053ffa14b38a8f93a9f")
	//srcStr, answer := []byte("03c73a7767c4294627455a4ad454fd5b0ec5cf4dbf9db0c1bd4ae3895ae754e3a8"), []byte("03c73a7767c4294627455a4ad454fd5b0ec5cf4dbf9db0c1bd4ae3895ae754e3a8")
	//srcStr, answer := []byte("f8799d3a6a2f90a683f0cf8904201b5e1860516761aa04b5eea6f47dd3d3b20bb85902f856c501808003c0e5a0b08d6cce6362a98451bf1091986b4d1e59efef2a4b0eff4bb8886682867289ae8082ffffa820109e6f1b9bf4cb377df1c3dbafa47ea0abae12a32484e1bf699dfbf2772b5ac2f17b00ffffff0080"), []byte("f86c9d3a6a2f90a683f0cf8904201b5e1860516761aa04b5eea6f47dd3d3b20bb84c02f849c501808003c0a0b08d6cce6362a98451bf1091986b4d1e59efef2a4b0eff4bb8886682867289aea020109e6f1b9bf4cb377df1c3dbafa47ea0abae12a32484e1bf699dfbf2772b5a80")
	//srcStr, answer := []byte("f8999e20cc9ef35b62b1335a9af34451a1c57fc07256f4df842497856bd6d808d9b87801f87501808004f86f02f86ce301a103d65fabd61151c76536b7a93f4c2731fd817f6c30f54e0d03b80631733847d121e301a103ef5bb9400ef6dfd55ec1924b3f9302064d132513af1852287aef7cfe850eb522e301a1024f450f9d909824f3a5726d586234398851d325006f0500bcc2f78dfbd92ccb72"), []byte("f8999e20cc9ef35b62b1335a9af34451a1c57fc07256f4df842497856bd6d808d9b87801f87501808004f86f02f86ce301a103d65fabd61151c76536b7a93f4c2731fd817f6c30f54e0d03b80631733847d121e301a103ef5bb9400ef6dfd55ec1924b3f9302064d132513af1852287aef7cfe850eb522e301a1024f450f9d909824f3a5726d586234398851d325006f0500bcc2f78dfbd92ccb72")
	//srcStr, answer := []byte("03d65fabd61151c76536b7a93f4c2731fd817f6c30f54e0d03b80631733847d121"), []byte("03d65fabd61151c76536b7a93f4c2731fd817f6c30f54e0d03b80631733847d121")


	dst := make([]byte, hex.DecodedLen(len(srcStr)))
	n, _ := hex.Decode(dst, srcStr)

	reAns := make([]byte, hex.DecodedLen(len(answer)))
	n2, _ := hex.Decode(reAns, answer)


	reStr, _ := RlpPaddingFilter(dst[:n])

	fmt.Printf("result = %v\nsrc = %x\ndst = %x\nans = %x\n", bytes.Equal(reAns[:n2], reStr), dst[:n], reStr, reAns[:n2])
}

func ExtPaddingFilter(src []byte) []byte {
        srcLen := len(src)
        if srcLen > 90 {
                return src
        //} else if srcLen > 8 && src[srcLen - 6] == 0x00 && src[srcLen - 5] == 0x00 && src[srcLen-4] == 0xff && src[srcLen-3] == 0xff {
        //} else if srcLen > 8 && src[srcLen - 5] == 0x00 && src[srcLen-4] == 0xff && src[srcLen-3] == 0xff {
        } else if srcLen == 40 && src[srcLen-4] == 0xff && src[srcLen-3] == 0xff {
                return src[:srcLen-8]
        }
        return src
}
*/

func RlpPaddingFilter(src []byte) (reRlp []byte, err error) {
	if len(src) <= 32 {
		return src, err
	}
	/*
	err = rlpCheckHeader(src)
	if err != nil {
		return reRlp, err
	}
	*/
	obj, err := rlpDecodeStructure(src)
	if err != nil {
		//return reRlp, err
		return src, nil
	}

	//fmt.Printf("\n\n")
	for _, v := range obj {
		/*if k == 0 {
			fmt.Printf("-1. len = %d, src = %x\n", len(src), src)
		fmt.Printf("%d. len = %d, obj = %x, kind = %d\n", k, v.length, v.data, v.kind)
		}*/
		reRlp = append(reRlp, v.data...)
	}
	//fmt.Printf("\n")

	return reRlp, err
}

func rlpCheckHeader(src []byte) (err error) {
	var totalLen int

	strLen := len(src)
	//if strLen <= 0 {
	/*
	if strLen < 32 {
		err = errors.New("rlp decode length error at simple RLP CheckHeader")
		return err
		//헤더 에러를 리턴해도 원본을 돌려보낼 순 있어야 겠네...
	}
	*/

	switch {
	case src[0] == 0x80:
		totalLen, err = 1, nil
	case src[0] < 0x80:
		_, _, totalLen, err = parseHeader(src, 1)
	case src[0] < 0xb8:
		_, _, totalLen, err = parseHeader(src, 2)
	case src[0] < 0xc0:
		_, _, totalLen, err = parseHeader(src, 3)
	case src[0] < 0xf8:
		_, _, totalLen, err = parseHeader(src, 4)
	default:
		_, _, totalLen, err = parseHeader(src, 5)
	}
	if strLen != totalLen {
		err = errors.New("rlp decode length error at simple RLP CheckHeader")
	}
	return err
}

func rlpDecodeStructure(src []byte) (reObj []rlpDS, err error) {
	var obj rlpDS

	tmpLen := 0
	for i := 0 ; i < len(src); {
		switch {
		case src[i] == 0x80:
			obj.kind = 0
			obj.data, obj.length, tmpLen, err = src[i:i+1], 1, 1, nil
		case src[i] < 0x80:
			obj.kind = 1
			obj.data, obj.length, tmpLen, err = rule1parse(src[i:])
		case src[i] < 0xb8:
			obj.kind = 2
			obj.data, obj.length, tmpLen, err = rule2parse(src[i:])
		case src[i] < 0xc0:
			obj.kind = 2
			obj.data, obj.length, tmpLen, err = rule3parse(src[i:])
		case src[i] < 0xf8:
			obj.kind = 3 
			obj.data, obj.length, tmpLen, err = rule4parse(src[i:])
		default:
			obj.kind = 3 
			obj.data, obj.length, tmpLen, err = rule5parse(src[i:])
		}
		if err != nil {
			break
		}
		
		reObj = append(reObj, obj)
		i += tmpLen
	}
	return reObj, err
}


func rule1parse(src []byte) (reStr []byte, reLen, totalLen int, err error) {
	totalLen = 0
	srcLen := len(src)
	for ; totalLen < srcLen && src[totalLen] < 0x80; totalLen += 1 {
	}
	tmpStr := src[:totalLen]
	//이곳에서 tmpStr 패팅한 다음에.
	//if tmpStr2, err2 := RlpPaddingFilter(tmpStr); err2 == nil {
	//	tmpStr = tmpStr2
	//}

	reLen = len(tmpStr)

	reStr = append(reStr, tmpStr[:]...)
	reLen = len(tmpStr)
	return reStr, reLen, totalLen, err
}


func rule2parse(src []byte) (reStr []byte, reLen int, totalLen int, err error) {

	dataIdx, _, totalLen, err := parseHeader(src, 2)
	if err != nil {
		return reStr, reLen, totalLen, err
	}
	tmpStr := ExtPaddingFilter(src[dataIdx:totalLen])
	//이곳에서 tmpStr 패팅한 다음에.
	//if tmpStr2, err2 := RlpPaddingFilter(tmpStr); err2 == nil {
	//	tmpStr = tmpStr2
	//}

	reStr, reLen = makepacket(tmpStr, 2)

	return reStr, reLen, totalLen, err
}

//reLen : padding 제거된후 전체 길이
//totalLen : 원래 전체 길이
func rule3parse(src []byte) (reStr []byte, reLen, totalLen int, err error) {

	dataIdx, _, totalLen, err := parseHeader(src, 3)
	if err != nil {
		return reStr, reLen, totalLen, err
	}
	tmpStr := ExtPaddingFilter(src[dataIdx:totalLen])
	//이곳에서 tmpStr 패팅한 다음에.
	//if tmpStr2, err2 := RlpPaddingFilter(tmpStr); err2 == nil {
	//	tmpStr = tmpStr2
	//}

	reStr, reLen = makepacket(tmpStr, 3)
	
	return reStr, reLen, totalLen, err
}

//reLen : padding 제거된후 전체 길이
//totalLen : 원래 전체 길이
func rule4parse(src []byte) (reStr []byte, reLen, totalLen int, err error) {
	var tmpPacket, tmpReStr []byte
	var packetList [][]byte
	var tmpPacketLen int

	dataIdx, _, totalLen, err := parseHeader(src, 4)
	if err != nil {
		return reStr, reLen, totalLen, err
	}
	
	tmpReLen, tmpTotalLen := int(0), int(0)
	for i := dataIdx; i < totalLen; {
		switch {
		case src[i] == 0x80:
			tmpReStr, tmpReLen, tmpTotalLen, err = src[i:i+1], 1, 1, nil
		case src[i] < 0x80:
			tmpReStr, tmpReLen, tmpTotalLen, err = rule1parse(src[i:])
		case src[i] < 0xb8:
			tmpReStr, tmpReLen, tmpTotalLen, err = rule2parse(src[i:])
		case src[i] < 0xc0:
			tmpReStr, tmpReLen, tmpTotalLen, err = rule3parse(src[i:])
		case src[i] < 0xf8:
			tmpReStr, tmpReLen, tmpTotalLen, err = rule4parse(src[i:])
		default:
			//panic("logically fail")
			tmpReStr, tmpReLen, tmpTotalLen, err = rule5parse(src[i:])
		}
		if err != nil || i + tmpTotalLen > totalLen {
			return src[:totalLen], totalLen, totalLen, nil
			//reStr, reLen = makepacket(src[dataIdx:totalLen], 4)
			//return reStr, reLen, totalLen, nil
		}

		packetList = append(packetList, tmpReStr)
		tmpPacket = append(tmpPacket, tmpReStr[:]...)
		tmpPacketLen += tmpReLen
		i += tmpTotalLen
		//totalLen += tmpTotalLen
	}
	//ExtHash의 경우만 되는 것.. 어차피 다른것을 파싱할려는 것도 아니니 아래와 같이 처리..
	if len(packetList) == 3 && len(packetList[0]) == 33 && len(packetList[1]) <= 5 && len(packetList[2]) <= 5 {
		pkLen := len(packetList[2])
		if packetList[2][pkLen - 1] == 0xff && packetList[2][pkLen - 2] == 0xff {
			reStr, reLen = makepacket(packetList[0][1:], 2)
		} else {
			reStr, reLen = makepacket(tmpPacket, 4)
		}
	} else {
		reStr, reLen = makepacket(tmpPacket, 4)
	}
	//reStr, reLen = makepacket(tmpPacket, 4)

	return reStr, reLen, totalLen, err
}

func rule5parse(src []byte) (reStr []byte, reLen, totalLen int, err error) {
	var tmpPacket, tmpReStr []byte
	//var packetList [][]byte
	var tmpPacketLen int

	dataIdx, _, totalLen, err := parseHeader(src, 5)
	if err != nil {
		return reStr, reLen, totalLen, err
	}

	for i := dataIdx; i < totalLen; {
		tmpReLen, tmpTotalLen := int(0), int(0)
		switch {
		case src[i] == 0x80:
			tmpReStr, tmpReLen, tmpTotalLen, err = src[i:i+1], 1, 1, nil
		case src[i] < 0x80:
			tmpReStr, tmpReLen, tmpTotalLen, err = rule1parse(src[i:])
		case src[i] < 0xb8:
			tmpReStr, tmpReLen, tmpTotalLen, err = rule2parse(src[i:])
		case src[i] < 0xc0:
			tmpReStr, tmpReLen, tmpTotalLen, err = rule3parse(src[i:])
		case src[i] < 0xf8:
			tmpReStr, tmpReLen, tmpTotalLen, err = rule4parse(src[i:])
		default:
			//panic("logically fail")
			tmpReStr, tmpReLen, tmpTotalLen, err = rule5parse(src[i:])
		}
		if err != nil || i + tmpTotalLen > totalLen {
			return src[:totalLen], totalLen, totalLen, nil
			//reStr, reLen = makepacket(src[dataIdx:totalLen], 5)
			//return reStr, reLen, totalLen, nil
		}

		tmpPacket = append(tmpPacket, tmpReStr[:]...)
		tmpPacketLen += tmpReLen
		i += tmpTotalLen
		//totalLen += tmpTotalLen
	}
	/*   ExtHash는 5의 케이스는 없는게 맞아서 우선 이렇게 처리함.
	//ExtHash의 경우만 되는 것.. 어차피 다른것을 파싱할려는 것도 아니니 아래와 같이 처리..
	if len(packetList) == 3 && len(packetList[0]) == 33 && len(packetList[1]) <= 5 && len(packetList[2]) <= 5 {
		pkLen := len(packetList[2])
		if packetList[2][pkLen - 1] == 0xff && packetList[2][pkLen - 2] == 0xff {
			reStr, reLen = makepacket(packetList[0][1:], 2)
		} else {
			reStr, reLen = makepacket(tmpPacket, 4)
		}
	} else {
		reStr, reLen = makepacket(tmpPacket, 4)
	}
	*/
	reStr, reLen = makepacket(tmpPacket, 5)

	return reStr, reLen, totalLen, err
}

func parseHeader(src []byte, flag int) (dataIdx, dataLen, totalLen int, err error) {
	var hexIdx int
	srcLen := len(src)
	if srcLen < 1 {
		err = errors.New("rlp decode length too small - 1... at simple RLP Decoder")
		return dataIdx, dataLen, totalLen, err
	}

	switch  {
	case flag == 2 || flag == 4:
		if flag == 2 {
			hexIdx = 0x80
		} else {
			hexIdx = 0xc0
		}

		dataLen = int(src[0]) - hexIdx
		totalLen = dataLen + 1
		dataIdx = 1
	case flag == 3 || flag == 5:
		if flag == 3 {
			hexIdx = 0xb7
		} else {
			hexIdx = 0xf7
		}

		if srcLen < int(src[0]) - hexIdx {
			err = errors.New("rlp decode length too small - 2... at simple RLP Decoder")
			return dataIdx, dataLen, totalLen, err
		}
		i:=1
		for ; i < srcLen && i <= int(src[0]) - hexIdx; i+=1 {
			dataLen *= 0x100
			dataLen += int(src[i])
		}
		totalLen = dataLen + i
		dataIdx = i
	}
	if totalLen > srcLen || dataLen > srcLen || dataLen <= 0 || dataIdx == totalLen {
	//if totalLen > srcLen || dataLen > srcLen || dataLen <= 0 {
		err = errors.New("rlp decode length error at simple RLP Decoder")
	//} else if totalLen < 32 { 
	//	err = errors.New("Return")
	} else if (hexIdx == 0x80 && dataLen >= 55) || (hexIdx == 0xb7 && dataLen < 55) || (hexIdx == 0xc0 && dataLen >= 55) || (hexIdx == 0xf7 && dataLen < 55) {
		err = errors.New("rlp decode length error at simple RLP Decoder")
	}
		//fmt.Printf("~~~~~ rlps dataIdx = %d, totalLen = %d, srcLen = %d, dataLen = %d, err = %v\n", dataIdx, totalLen, srcLen, dataLen, err)
	return dataIdx, dataLen, totalLen, err
}

func makepacket(data []byte, flag int) (packet []byte, packetLen int) {
	var tmpByte byte
	var procData []byte
	var tmpHeader []byte

	//dataLen := len(data)
	if tmpData, err := RlpPaddingFilter(data); err == nil {
		procData = tmpData
	} else {
		procData = data
	}
	//procData = data
	dataLen := len(procData)
	
	if dataLen <= 55 {
		if flag == 2 {
			tmpByte = uint8(0x80 + dataLen)
		} else { //4
			tmpByte = uint8(0xc0 + dataLen)
		}
		packet = append(packet, tmpByte)
		packet = append(packet, procData[:dataLen]...)
	} else {
		div := 0xffffff
		dlen := dataLen
		for ; div >= 0; div /= 0x100 {
			if dlen > div && div > 0 {
				tmpByte = uint8(dlen/div)
				tmpHeader = append(tmpHeader, tmpByte)
				div %= (div+1)
			} else if div == 0 {
				tmpByte = uint8(dlen)
				tmpHeader = append(tmpHeader, tmpByte)
				break
			}
		}
		tmpHeaderLen := len(tmpHeader)
		if flag == 3 {
			tmpByte = uint8(0xb7 + tmpHeaderLen)
		} else { //5
			tmpByte = uint8(0xf7 + tmpHeaderLen)
		}
		packet = append(packet, tmpByte)
		packet = append(packet, tmpHeader...) 
		packet = append(packet, procData[:dataLen]...)
	}
	packetLen = len(packet)
	return packet, packetLen
}

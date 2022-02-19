package queries

import (
	"errors"
	"fmt"
	"io/ioutil"
	"strconv"
	"strings"
)

type ResultCode uint8
type RType uint16

const (
	ARECORD  RType = 0x0001
	NSRECORD       = 0x0002
	CNAME          = 0x0005
	SOA            = 0x0006
	WKS            = 0x000b // wow
	PTR            = 0x000c
	MXRECORD       = 0x000f
	SRV            = 0x0021
	AAAA           = 0x001c
	ANYRES         = 0x00ff // resource records (typically SOA, MX, NS and MX)
)

const (
	NOERROR ResultCode = iota
	FORMERR
	SERVFAIL
	NXDOMAIN
	NOTIMP
	REFUSED
)

var ResultCodeNames = map[ResultCode]string{
	NOERROR:  "NOERROR",
	FORMERR:  "FORMERR",
	SERVFAIL: "SERVFAIL",
	NXDOMAIN: "NXDOMAIN",
	NOTIMP:   "NOTIMP",
	REFUSED:  "REFUSED",
}

var RTypeNames = map[RType]string{
	ARECORD:  "A",
	NSRECORD: "NS",
	CNAME:    "CNAME",
	SOA:      "SOA",
	WKS:      "WELLKNOWN",
	PTR:      "PTR",
	MXRECORD: "MX",
	SRV:      "SRV",
	AAAA:     "AAAA",
	ANYRES:   "ANY-RES",
}

func getResultCode(num uint8) ResultCode {

	// todo: this should be a case
	if num == 0 {
		return NOERROR
	} else if num == 1 {
		return FORMERR
	} else if num == 2 {
		return SERVFAIL
	} else if num == 3 {
		return NXDOMAIN
	} else if num == 4 {
		return NOTIMP
	} else if num == 5 {
		return REFUSED
	}

	return 0 // is this ok?
}

func getRecordTypeName(rt RType) string {
	return RTypeNames[rt]
}

// todo: rename to packetBuf
type bytePacketBuffer struct {
	buf []uint8
	pos int
	len int
}

type Header struct {
	queryId            uint16
	rawBytes           *[]uint8 // store all the bytes as a reference
	recursionDesired   bool
	isTruncatedMessage bool
	recursionAvailable bool
	isAuthoritative    bool
	opcode             uint8
	response           bool // query or response. todo: change to a type?
	resCode            ResultCode
	dnsSec             bool
	questions          uint16
	answers            uint16
	authoritative      uint16
	additional         uint16
}

type Query struct {
	name  string
	qtype RType  // yeah feels weird. qtype vs rtype (query is requessting a record type)
	class uint16 // always 1 (IN)
}

type Response struct {
	name        string
	ttl         uint32
	octets      []uint8
	recordType  RType
	recordClass uint8
}

func (r *Response) asStr() string {
	if len(r.octets) == 4 {
		return fmt.Sprintf("%d.%d.%d.%d", r.octets[0], r.octets[1], r.octets[2], r.octets[3])
	}
	return "Some ipv6 formatted ipv6 specialness"
}

func (h *Header) QueryIdHex() string {
	return fmt.Sprintf("0x%x", h.queryId)
}

func (h *Header) resCodeStr() string {
	return ResultCodeNames[h.resCode]
}

func (h *Header) IsResponse() bool {
	return h.response
}

func (q *Query) rTypeStr() string {
	return RTypeNames[q.qtype]
}

func NewBytePacketBuffer() *bytePacketBuffer {
	return &bytePacketBuffer{
		buf: make([]uint8, 512),
		pos: 0,
		len: 0,
	}
}

func DecodeBuffer(b *bytePacketBuffer) (*Header, *Query, *[]Response, error) {
	// returns decoded header, query, response

	rawBytes := b.getAll()
	queryHeader, _ := b.getRange(0, 12)

	b.seek(4) // 4th byte is where the next 9 start

	header := &Header{
		rawBytes:           rawBytes,
		queryId:            uint16(queryHeader[0])<<8 | uint16(queryHeader[1]),
		response:           queryHeader[2]&0x80 == 0x80, // 128
		opcode:             (queryHeader[2] << 1) >> 4,
		isAuthoritative:    queryHeader[2]&4 == 1,
		isTruncatedMessage: queryHeader[2]&2 == 1,
		recursionDesired:   queryHeader[2]&1 == 1,
		recursionAvailable: queryHeader[3]&128 == 128,
		dnsSec:             ((queryHeader[3] << 1) >> 5) == 1,
		resCode:            getResultCode(queryHeader[3] & 0x0f), // 15
		questions:          b.get16(),
		answers:            b.get16(),
		authoritative:      b.get16(),
		additional:         b.get16(),
	}

	query, _ := getQueryFromBuffer(b)

	var responses *[]Response

	if header.response {
		// skip over the next four bytes, they are the name indexes
		// we dont need them yet
		responses, _ = getResponsesFromBuffer(b)

	} else {
		responses = nil
	}

	return header, query, responses, nil
}

func getResponsesFromBuffer(b *bytePacketBuffer) (*[]Response, error) {

	responses := []Response{}

	labels := []string{}
	var length uint8
	queryOffset := b.getPos()

	for {
		if b.eof() {
			break
		}

		for {
			length, _ = b.read()

			if length == 0 {
				break
			}

			if length>>6 == 3 {
				// is jump byte
				fmt.Println("is jump byte (first two msb set)")
				nextByte := b.readAhead()

				// combine length and the byte proceeding it into a uint16
				combined := uint16(length)<<8 | uint16(nextByte)<<0

				mask := uint16(0xc000) // always two msb
				// offset is xor of mask & position indicated in combined bytes
				queryOffset = int(combined ^ mask)

			}

			label, _ := b.getRange(queryOffset, queryOffset+int(length)+1)
			labels = append(labels, string(label))
			queryOffset += int(length) + 1
			b.seek(queryOffset) // move queryoffset to new start position
		}

		response := Response{
			recordType:  RType(b.get16()),
			recordClass: uint8(b.get16()),
			ttl:         uint32(b.get32()),
		}

		respLength := b.get16()

		// set octets
		if respLength == 4 {
			response.octets = []uint8{b.get8(), b.get8(), b.get8(), b.get8()}
		}

		response.name = strings.Join(labels, ".")

		responses = append(responses, response)
	}

	return &responses, nil

}

func getQueryFromBuffer(b *bytePacketBuffer) (*Query, error) {

	labels := []string{}
	var length uint8
	queryOffset := 12 // 12th byte offset is where the response starts
	b.seek(queryOffset)

	for {
		length, _ = b.read()

		if length == 0 {
			break
		}

		if length>>6 == 3 {
			// is jump byte
			fmt.Println("is jump byte (first two msb set)")
			nextByte := b.readAhead()

			// combine length and the byte proceeding it into a uint16
			combined := uint16(length)<<8 | uint16(nextByte)<<0

			mask := uint16(0xc000) // always two msb
			// offset is xor of mask & position indicated in combined bytes
			queryOffset = int(combined ^ mask)

		}

		label, _ := b.getRange(queryOffset, queryOffset+int(length)+1)
		labels = append(labels, string(label))
		queryOffset += int(length) + 1
		b.seek(queryOffset) // move queryoffset to new start position
	}

	// next two are type and class
	recordType := b.get16()
	recordClass := b.get16()

	s := strings.Join(labels, ".")
	q := Query{
		name:  s,
		qtype: RType(recordType),
		class: recordClass,
	}

	return &q, nil
}

func (b *bytePacketBuffer) getAll() *[]uint8 {
	return &b.buf
}

func (b *bytePacketBuffer) getPos() int {
	return b.pos
}

func (b *bytePacketBuffer) reset() {
	b.pos = 0
}

func (b *bytePacketBuffer) next() {
	b.pos += 1
}

func (b *bytePacketBuffer) eof() bool {
	return b.pos > b.len
}

func (b *bytePacketBuffer) skip(i int) {
	b.pos += i
	if b.pos >= 512 {
		b.pos = 0 // wrap
	}
}

func (b *bytePacketBuffer) prev() {
	b.pos -= 1
	if b.pos < 0 {
		// can nee
		b.pos = 0
	}
}

func (b *bytePacketBuffer) step(steps int) {
	b.pos += steps
}

func (b *bytePacketBuffer) seek(pos int) {
	b.pos = pos
}

func (b *bytePacketBuffer) read() (uint8, error) {
	if b.pos >= 512 {
		errors.New("Went beyond end of buffer")
	}

	val := b.buf[b.pos]
	b.next()

	return val, nil
}

func (b *bytePacketBuffer) readAhead() uint8 {
	// this reads one ahead then rewinds
	pos := b.pos
	val, _ := b.read()
	b.seek(pos) // go back
	return val
}

func (b *bytePacketBuffer) get(pos int) (uint8, error) {
	if pos >= 512 {
		errors.New("Went beyond end of buffer")
	}

	return b.buf[pos], nil
}

func (b *bytePacketBuffer) unsafeGet(pos int) uint8 {
	if pos >= 512 {
		return 0x0
	}

	return b.buf[pos]
}

func (b *bytePacketBuffer) getRange(start int, len int) ([]uint8, error) {
	if start+len >= 512 {
		errors.New("Went beyond end of buffer")
	}

	return b.buf[start:len], nil
}

func (b *bytePacketBuffer) get8() uint8 {
	val, _ := b.read()
	return val
}

func (b *bytePacketBuffer) get16() uint16 {
	one, _ := b.read()
	two, _ := b.read()

	return uint16(one)<<8 | uint16(two)<<0
}

func (b *bytePacketBuffer) get32() uint32 {
	one, _ := b.read()
	two, _ := b.read()
	three, _ := b.read()
	four, _ := b.read()

	return uint32(one)<<24 | uint32(two)<<16 | uint32(three)<<8 | uint32(four)<<0
}

func NewBytePacketBufferFromFile(path string) *bytePacketBuffer {

	pBuf := NewBytePacketBuffer()

	data, err := ioutil.ReadFile(path)

	if err != nil {
		fmt.Print(err)
	}

	pBuf.len = len(data)

	pBuf.buf = data[:512] // trunc to 512

	return pBuf
}

func DumpQuery(b *bytePacketBuffer) {
	fmt.Println("Dumping query info")
	fmt.Println("------------------")

	// first 12 bytes are the heder
	queryHeader, _ := b.getRange(0, 12)

	fmt.Println("Raw query header")

	dumpAsHex(queryHeader)

	fmt.Println("Query identifier:")
	id1, id2 := queryHeader[0], queryHeader[1]

	fmt.Println(fmt.Sprintf("%s", strconv.FormatUint(uint64(id1), 2)))
	fmt.Println(fmt.Sprintf("%s", strconv.FormatUint(uint64(id2), 2)))

	fmt.Println("->", asHexString(id1), asHexString(id2), "(", id1, id2, ")")

	fmt.Println("----")

	// next 2 bytes (msb)
	// first byte:
	// 0:   QR (0 == qr, 1 == resp)
	// 1-4: Opcode
	// 5:   AA (authoritative answer): 1 for auth, 0 for not
	// 6:   TC (truncated msg): 1 if msg > 512b
	// 7:   RD (recursion desired): 1 if server should resolve recursively

	// second byte:
	// 0:   RA (recursion available): set by server if recursion allowed
	// 1-3: reserved (for DNSSEC)
	// 4-7: Rcode

	// query
	// 01: 0 0 0 0 0 0 0 1   ( 1)
	// 20: 0 0 1 0 0 0 0 0   (32)
	// response
	// 81: 1 0 0 0 0 0 0 1   (129)
	// 80: 1 0 0 0 0 0 0 0   (128)

	trail1, trail2 := queryHeader[2], queryHeader[3]
	var isQuery bool

	fmt.Println("Type:")
	if trail1&128 == 128 {
		fmt.Println(" -> Response")
		isQuery = false
	} else if trail1&128 == 0 {
		fmt.Println(" -> Query")
		isQuery = true
	} else {
		fmt.Println(" -> Unknown [WARN]")
	}

	fmt.Println("Opcode:")
	opcode := (trail1 << 1) >> 4
	if opcode == 0 {
		fmt.Println(" -> 0")
	} else {
		fmt.Println(opcode, " -> Unknown [WARN]")
	}

	fmt.Println("AA Authoritative answer:")
	if trail1&4 == 1 {
		fmt.Println(" -> yes")
	} else {
		fmt.Println(" -> no")
	}

	fmt.Println("TC Truncated:")
	if trail1&2 == 1 {
		fmt.Println(" -> yes")
	} else {
		fmt.Println(" -> no")
	}

	fmt.Println("RD Recursion desired:")
	if trail1&1 == 1 {
		fmt.Println(" -> yes")
	} else {
		fmt.Println(" -> no")
	}

	fmt.Println("----")

	// 2nd byte

	fmt.Println("RA Recursive:")
	if trail2&128 == 128 {
		fmt.Println(" -> yes")
	} else {
		fmt.Println(" -> no")
	}

	fmt.Println("DNSSEC:")
	dnssec := (trail2 << 1) >> 5
	fmt.Println(" ->", dnssec)

	rcode := trail2 & 15
	fmt.Println("RCode")
	fmt.Println(" -> ", rcode)

	// flags
	queryCount, _ := b.get(4)
	answerCount, _ := b.get(5)
	authorityCount, _ := b.get(6)
	additionalCount, _ := b.get(7)

	fmt.Println("Query count: ", queryCount)
	fmt.Println("Answer count: ", answerCount)
	fmt.Println("Authority count: ", authorityCount)
	fmt.Println("Additional count: ", additionalCount)

	// query section

	queryOffset := 12 // starts at 12th offset (13th byte, 0-idx)
	labels := []string{}
	var length uint8
	b.seek(queryOffset)

	for {
		length, _ = b.read()
		if length == 0 {
			break
		}

		if length>>6 == 3 {
			// is jump byte
			fmt.Println("is jump byte (first two msb set)")
			nextByte := b.readAhead()

			// combine length and the byte proceeding it into a uint16
			combined := uint16(length)<<8 | uint16(nextByte)<<0

			mask := uint16(0xc000) // always two msb
			// offset is xor of mask & position indicated in combined bytes
			queryOffset = int(combined ^ mask)

		}

		label, _ := b.getRange(queryOffset, queryOffset+int(length)+1)
		labels = append(labels, string(label))
		queryOffset += int(length) + 1
		b.seek(queryOffset) // move queryoffset to new start position

	}

	fmt.Println("Query:")
	fmt.Println(" ->", strings.Join(labels, "."))

	fmt.Println("Cursor pos:", b.getPos())

	// the next 2x 2-bytes are type & class
	recordType := b.get16()
	recordClass := b.get16()

	fmt.Println("recordClass", recordClass)
	fmt.Println("recordType", recordType)

	if !isQuery {
		// name is two bytes (read separately for ease)
		fmt.Println("Record name indexes:")
		nameIdx1, _ := b.read()
		nameIdx2, _ := b.read()

		// type
		recordType := b.get16()
		fmt.Println("Record type:")
		fmt.Println(" ->", recordType)

		recordClass := b.get16()
		fmt.Println("Record class:")
		fmt.Println(" -> ", recordClass)

		// next 4 bytes are TTL
		ttl := b.get32()
		fmt.Println("ttl:")
		fmt.Println(" ->", ttl, "seconds")

		// byte-length answer
		respLength := b.get16()
		fmt.Println("Response class:")
		if respLength == 4 {
			fmt.Println(" -> ipv4")
		} else {
			fmt.Println(" -> ipv6")
		}

		if respLength == 4 {
			octets := []uint8{b.get8(), b.get8(), b.get8(), b.get8()}
			fmt.Println("ipv4:")
			fmt.Println(fmt.Sprintf(" -> %d.%d.%d.%d", octets[0], octets[1], octets[2], octets[3]))
		} else if respLength == 6 {
			// todo. dunno how to deal with this yet
			fmt.Println("ipv6: [TODO]")
		}

		// figure out the name field
		fmt.Println(nameIdx1)
		fmt.Println(nameIdx2)
	}
}

func dumpResponse() {
	// dumps a query response out
}

func asHexString(i uint8) string {
	return fmt.Sprintf("%x", i)
}

func dumpAsHex(b []uint8) {
	s := []string{}
	for i, j := range b {
		s = append(s, fmt.Sprintf("%d: %x", i, j))
	}
	fmt.Println("[", strings.Join(s, ", "), "]")
}

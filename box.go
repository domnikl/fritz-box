package fritzBox

import (
	"crypto/md5"
	"encoding/binary"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"io"
	"io/ioutil"
	"net/http"
	"strconv"
	"strings"
	"unicode/utf16"
)

// FritzBox stores all data needed to access the box
type FritzBox struct {
	password string
	username string
	baseURL  string
	sid      string
}

// SessionInfo describes the challenge and SID used for authorization
type SessionInfo struct {
	SID       string `xml:"SID"`
	Challenge string `xml:"Challenge"`
}

// New creates a new instance of FritzBox
func New(password string) FritzBox {
	f := FritzBox{password: password}
	f.baseURL = "http://fritz.box"

	return f
}

// GetTemperature reads the temperature from ain and returns a float in °Celsius
func (f FritzBox) GetTemperature(ain string) (float64, error) {
	v, err := f.request("gettemperature", ain)

	if err != nil {
		return .0, err
	}

	v2, err := strconv.ParseFloat(v, 64)

	if err != nil {
		return .0, err
	}

	return v2 * 0.1, nil
}

// GetPower returns the kW/h consumed by the device on ain
func (f FritzBox) GetPower(ain string) (float64, error) {
	v, err := f.request("getswitchpower", ain)

	if err != nil {
		return .0, err
	}

	v2, err := strconv.ParseFloat(v, 64)

	if err != nil {
		return .0, err
	}

	return v2 * 0.001, nil
}

func (f *FritzBox) login() error {
	resp, err := http.Get(f.baseURL + "/login_sid.lua?sid=" + f.sid)

	if err != nil {
		return err
	}

	if resp.StatusCode != 200 {
		return errors.New("Expected HTTP Status Code 200, but got: " + strconv.Itoa(resp.StatusCode))
	}

	session, err := parseLoginResponse(resp.Body)

	if err != nil {
		return err
	}

	if session.SID != "0000000000000000" {
		// session is still valid
		f.sid = session.SID
		return nil
	}

	response := solveChallenge(*session, f.password)

	resp, err = http.Get(f.baseURL + "/login_sid.lua?response=" + response)

	if err != nil {
		return err
	}

	if resp.StatusCode != 200 {
		return errors.New("Expected HTTP Status Code 200, but got: " + strconv.Itoa(resp.StatusCode))
	}

	newSessionInfo, err := parseLoginResponse(resp.Body)

	if err != nil {
		return err
	}

	f.sid = newSessionInfo.SID

	return nil
}

func (f FritzBox) request(command string, ain string) (string, error) {
	err := f.login()

	if err != nil {
		return "", err
	}

	url := f.baseURL + "/webservices/homeautoswitch.lua?sid=" + f.sid + "&ain=" + ain + "&switchcmd=" + command

	resp, err := http.Get(url)

	if err != nil {
		return "", err
	}

	if resp.StatusCode != 200 {
		return "", errors.New("Expected HTTP Status Code 200, but got: " + strconv.Itoa(resp.StatusCode))
	}

	defer resp.Body.Close()
	r, err := ioutil.ReadAll(resp.Body)

	if err != nil {
		return "", err
	}

	body := strings.TrimSpace(string(r))

	if body == "inval" {
		return "", errors.New("invalid value")
	}

	return body, nil
}

func parseLoginResponse(body io.ReadCloser) (*SessionInfo, error) {
	defer body.Close()
	buffer, err := ioutil.ReadAll(body)

	if err != nil {
		return nil, err
	}

	s := &SessionInfo{}
	err = xml.Unmarshal(buffer, s)

	if err != nil {
		return nil, err
	}

	return s, nil
}

func solveChallenge(s SessionInfo, password string) string {
	codes := utf16.Encode([]rune(s.Challenge + "-" + password))
	b := convertUTF16ToLittleEndianBytes(codes)

	h := md5.New()
	h.Write(b)

	x := s.Challenge + "-" + hex.EncodeToString(h.Sum(nil))

	return x
}

func convertUTF16ToLittleEndianBytes(u []uint16) []byte {
	b := make([]byte, 2*len(u))
	for index, value := range u {
		binary.LittleEndian.PutUint16(b[index*2:], value)
	}
	return b
}

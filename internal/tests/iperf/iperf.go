package iperf

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/edwarnicke/exechelper"
	"github.com/networkservicemesh/api/pkg/api/networkservice"
	"github.com/pkg/errors"
	"github.com/vishvananda/netns"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
)

type IperfResult struct {
	Start struct {
		Connected []struct {
			Socket     int    `json:"socket"`
			LocalHost  string `json:"local_host"`
			LocalPort  int    `json:"local_port"`
			RemoteHost string `json:"remote_host"`
			RemotePort int    `json:"remote_port"`
		} `json:"connected"`
		Version    string `json:"version"`
		SystemInfo string `json:"system_info"`
		Timestamp  struct {
			Time     string `json:"time"`
			Timesecs int    `json:"timesecs"`
		} `json:"timestamp"`
		ConnectingTo struct {
			Host string `json:"host"`
			Port int    `json:"port"`
		} `json:"connecting_to"`
		Cookie        string `json:"cookie"`
		TcpMssDefault int    `json:"tcp_mss_default"`
		SockBufsize   int    `json:"sock_bufsize"`
		SndbufActual  int    `json:"sndbuf_actual"`
		RcvbufActual  int    `json:"rcvbuf_actual"`
		TestStart     struct {
			Protocol   string `json:"protocol"`
			NumStreams int    `json:"num_streams"`
			Blksize    int    `json:"blksize"`
			Omit       int    `json:"omit"`
			Duration   int    `json:"duration"`
			Bytes      int    `json:"bytes"`
			Blocks     int    `json:"blocks"`
			Reverse    int    `json:"reverse"`
			Tos        int    `json:"tos"`
		} `json:"test_start"`
	} `json:"start"`
	Intervals []struct {
		Streams []struct {
			Socket        int     `json:"socket"`
			Start         float64 `json:"start"`
			End           float64 `json:"end"`
			Seconds       float64 `json:"seconds"`
			Bytes         int     `json:"bytes"`
			BitsPerSecond float64 `json:"bits_per_second"`
			Omitted       bool    `json:"omitted"`
			Sender        bool    `json:"sender"`
		} `json:"streams"`
		Sum struct {
			Start         float64 `json:"start"`
			End           float64 `json:"end"`
			Seconds       float64 `json:"seconds"`
			Bytes         int     `json:"bytes"`
			BitsPerSecond float64 `json:"bits_per_second"`
			Omitted       bool    `json:"omitted"`
			Sender        bool    `json:"sender"`
		} `json:"sum"`
	} `json:"intervals"`
	End struct {
		Streams []struct {
			Sender struct {
				Socket        int     `json:"socket"`
				Start         int     `json:"start"`
				End           float64 `json:"end"`
				Seconds       float64 `json:"seconds"`
				Bytes         int     `json:"bytes"`
				BitsPerSecond float64 `json:"bits_per_second"`
				Sender        bool    `json:"sender"`
			} `json:"sender"`
			Receiver struct {
				Socket        int     `json:"socket"`
				Start         int     `json:"start"`
				End           float64 `json:"end"`
				Seconds       float64 `json:"seconds"`
				Bytes         int     `json:"bytes"`
				BitsPerSecond float64 `json:"bits_per_second"`
				Sender        bool    `json:"sender"`
			} `json:"receiver"`
		} `json:"streams"`
		SumSent struct {
			Start         int     `json:"start"`
			End           float64 `json:"end"`
			Seconds       float64 `json:"seconds"`
			Bytes         int     `json:"bytes"`
			BitsPerSecond float64 `json:"bits_per_second"`
			Sender        bool    `json:"sender"`
		} `json:"sum_sent"`
		SumReceived struct {
			Start         int     `json:"start"`
			End           float64 `json:"end"`
			Seconds       float64 `json:"seconds"`
			Bytes         int     `json:"bytes"`
			BitsPerSecond float64 `json:"bits_per_second"`
			Sender        bool    `json:"sender"`
		} `json:"sum_received"`
		CpuUtilizationPercent struct {
			HostTotal    float64 `json:"host_total"`
			HostUser     float64 `json:"host_user"`
			HostSystem   float64 `json:"host_system"`
			RemoteTotal  float64 `json:"remote_total"`
			RemoteUser   float64 `json:"remote_user"`
			RemoteSystem float64 `json:"remote_system"`
		} `json:"cpu_utilization_percent"`
	} `json:"end"`
}

type ResultByIP struct {
	Ip string
	Result IperfResult
}

type ResultTable struct {
	IperfTable map[string][]ResultByIP `json:"iperf_table"`
	Mut sync.Mutex
	Err []string
}

func WriteFile(clientMech, endpointMech string, cN, eN int) error {
	dir := "results"
	_, err := os.Stat(dir)
	if os.IsNotExist(err){
		err := os.Mkdir(dir, 0755)
		if err != nil {
			return err
		}
	}

	err = writeJson(&Result, dir, clientMech, endpointMech, cN, eN)
	if err != nil {
		return err
	}

	err = writeCSV(&Result, dir, clientMech, endpointMech, cN, eN)
	if err != nil {
		return err
	}

	//err = writeServerError(dir, clientMech, endpointMech, cN, eN)
	//if err != nil {
	//	return err
	//}

	//err = writeServerOutput(dir, clientMech, endpointMech, cN, eN)
	//if err != nil {
	//	return err
	//}

	return nil
}

// write full result json, just in case
func writeJson(table *ResultTable, dir, clientMech, endpointMech string, cN, eN int) error {
	filename := fmt.Sprintf("%v/%v_to_%v_%v_to_%v.json", dir, clientMech, endpointMech, cN, eN)
	file, err := os.OpenFile(filename, os.O_APPEND|os.O_CREATE|os.O_WRONLY, os.ModePerm)
	if err != nil {
		return err
	}

	b, err := json.Marshal(table.IperfTable)
	if err != nil {
		return err
	}

	_, err = file.Write(b)
	if err != nil {
		return err
	}

	return nil
}

// write result in csv processed for plotting in gnuplot
func writeCSV(table *ResultTable, dir, clientMech, endpointMech string, cN, eN int) error{
	filename := fmt.Sprintf("%v/%v_to_%v_%v_to_%v.csv", dir, clientMech, endpointMech, cN, eN)
	file, err := os.OpenFile(filename, os.O_APPEND|os.O_CREATE|os.O_WRONLY, os.ModePerm)
	if err != nil {
		return err
	}
	var columns [][]string
	for key, val := range table.IperfTable {
		for _, v := range val {
			var sums []string
			for _, i := range v.Result.Intervals {
				sums = append(sums, strconv.Itoa(i.Sum.Bytes/(1024*1024)))
			}
			columns = append(columns, append([]string{key + "(" + v.Ip + ")" }, sums...))
		}
	}
	if len(columns) == 0 {
		return errors.New("empty result")
	}

	var rows = make([][]string, len(columns[0]))
	for i, col := range columns {
		for j := range col {
			if len(rows[j]) == 0 {
				rows[j] = make([]string, len(columns[0]))
			}
			rows[j][i] = columns[i][j]
		}
	}

	str := strings.Builder{}
	for i, r := range rows {
		str.WriteString(strconv.Itoa(i - 1) + "," + strings.Join(r, ",") + "\n")
	}

	_, err = file.WriteString(str.String())
	if err != nil {
		return err
	}

	return nil
}

var Result = ResultTable{IperfTable: map[string][]ResultByIP{}, Err: []string{}}
func Cmd(ipnet *net.IPNet, clientHandle netns.NsHandle, conn *networkservice.Connection) error {
	if ipnet == nil {
		return nil
	}

	// start client
	var buff bytes.Buffer
	var errBuff strings.Builder
	iperfStr := fmt.Sprintf("iperf3 -t 60 -M 1400 -J -c %s", ipnet.IP.String())
	if err := exechelper.Run(iperfStr,
		exechelper.WithEnvirons(os.Environ()...),
		exechelper.WithStdout(io.MultiWriter(os.Stdout, &buff)),
		exechelper.WithStderr(io.MultiWriter(os.Stderr, &errBuff)),
		exechelper.WithNetNS(clientHandle),
	); err != nil {
		return errors.Wrapf(err, "failed to measure throughput with command %q", iperfStr)
	}

	var res IperfResult
	err := json.Unmarshal(buff.Bytes(), &res)
	if err != nil {
		return err
	}

	Result.Mut.Lock()
	Result.IperfTable[conn.Id] = append(Result.IperfTable[conn.Id], ResultByIP{Result: res, Ip: ipnet.IP.String()})
	Result.Err = append(Result.Err, errBuff.String())
	Result.Mut.Unlock()

	return nil
}

func StartServer(ipnet *net.IPNet, endpointHandle netns.NsHandle) error{
	iperfSrvStr := fmt.Sprintf("iperf3 -s --bind %s", ipnet.IP.String())
	err := exechelper.Run(iperfSrvStr,
		exechelper.WithEnvirons(os.Environ()...),
		exechelper.WithStdout(bytes.NewBuffer([]byte{})),
		exechelper.WithStderr(bytes.NewBuffer([]byte{})),
		exechelper.WithNetNS(endpointHandle))
	if err != nil {
		return err
	}

	return nil
}

func writeServerError(dir, clientMech, endpointMech string, cN, eN int) error {
	filename := fmt.Sprintf("%v/errors_%v_to_%v_%v_to_%v.txt", dir, clientMech, endpointMech, cN, eN)
	file, err := os.OpenFile(filename, os.O_APPEND|os.O_CREATE|os.O_WRONLY, os.ModePerm)
	if err != nil {
		return err
	}

	_, err = file.WriteString(strings.Join(Result.Err, ";"))
	if err != nil {
		return err
	}

	//for k,v := range srvr.serverErrors {
	//	_, err = file.WriteString(k + "\n" + strings.Join(v, "\n"))
	//	_, err = file.WriteString(strings.Repeat("|", 30))
	//	if err != nil {
	//		continue
	//	}
	//}

	return nil
}

func writeServerOutput(dir, clientMech, endpointMech string, cN, eN int) error {
	filename := fmt.Sprintf("%v/server_output_%v_to_%v_%v_to_%v.txt", dir, clientMech, endpointMech, cN, eN)
	file, err := os.OpenFile(filename, os.O_APPEND|os.O_CREATE|os.O_WRONLY, os.ModePerm)
	if err != nil {
		return err
	}

	if len(srvr.serverOutput) == 0 {
		return nil
	}

	for k,v := range srvr.serverOutput {
		_, err = file.WriteString(k + "\n" + strings.Join(v, "\n"))
		_, err = file.WriteString(strings.Repeat("|", 30))
		if err != nil {
			continue
		}
	}

	return nil
}

var srvr = &srv{
	serverOutput: map[string][]string{},
	serverErrors: map[string][]string{},
}
type srv struct {
	serverErrors map[string][]string
	serverOutput map[string][]string
	mut sync.Mutex
}
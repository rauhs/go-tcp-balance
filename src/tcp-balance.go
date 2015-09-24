package main

////////////////////////////////////////////////////////////////////////////////
// tcp-balance.go
// This script load balances incoming TCP connections onto multiple target
// machines. It works with any applications, though the port 22 is assumed. So
// this is really for SSH load balancing.
// It listends on a specific network interface and port of the computer it is
// run.
// Upon a connecting client it will check all target hosts for their load and
// connect itself to the one with the most resources available (like
// waterfilling algorithm). It will then pipe every packet that it receives
// from either side to the other side. See the code for more details on
// specific parts.
// For this script to understand you will have to read up on go-routines.
// Google it.
// TODO:
// Kill CMD (PHP) invoked to figure out load after X ms
// EDIT: DONE
//
////////////////////////////////////////////////////////////////////////////////

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"strconv"
	"sync"
	"syscall"
	"time"
)

////////////////////////////////////////////////////////////////////////////////
// Constants. Modify me:

const VERSION = "0.3.0"

// Struct that holds information about one backend server
type Host struct {
	Name       string     // Server name, like hoek3
	MaxLoad    float64    // eq # of CPU cores. Wanted: Load <= MaxLoad
	Load1m     float64    // 1 min load of the target
	Status     HostStatus // Unknown, Offline, Online, OnlineWithLoad
	DispCount  uint64     // History of how many clients have been dispatched
	ActiveConn uint64     // Actively connected clients
}

// For more info look down in the source code. Give the connection this much
// time before sending some keep alive probes and drop the connection. Two days
// allows people to reuse the connection even after a day of their laptop in
// standbye as long as their IP hasn't changed and their O/S can handle it.
// After this time, the network layer will send 9 probes separated by 75seconds
// If all of them fail the connection will be dropped.
// For linux this is limited to 2^15
//const TCP_KEEP_ALIVE = 32766 // ~9h
const TCP_KEEP_ALIVE = 120 // default val
// const TCP_KEEP_ALIVE = 10

// Timeout of TCP read. Ie if no command is sent through SSH. Client might
// still be there.
const TCP_READ_TIMEOUT = 48 * time.Hour

// To find out MaxLoad of a system you can run "nproc" on linux systems. You
// may increase it if the processors can do some hypterthreading. But I
// wouldn't recommend that.

// The main cluster information. The MaxLoad is the load the target computer
// can still handle well. It should not go above it.
// The status is re-populated every time a new client connects.
var REIGN = map[string][]Host{
	"h": []Host{
		{"h1.example.edu", 8, -1, Unknown, 0, 0},
		{"h2.example.edu", 8, -1, Unknown, 0, 0},
		{"h3.example.edu", 8, -1, Unknown, 0, 0},
		{"h4.example.edu", 8, -1, Unknown, 0, 0},
		{"h5.example.edu", 8, -1, Unknown, 0, 0},
		{"h6.example.edu", 8, -1, Unknown, 0, 0},
		{"h7.example.edu", 12, -1, Unknown, 0, 0},
		{"h8.example.edu", 12, -1, Unknown, 0, 0}},
	"x": []Host{
		{"x.example.edu", 62, -1, Unknown, 0, 0}},
	"o": []Host{
		{"o1.example.edu", 32, -1, Unknown, 0, 0},
		{"o2.example.edu", 8, -1, Unknown, 0, 0}},
}

// Just an alias to make the code more readable
type HostStatus int

// Host status constants
const (
	OnlineWithLoad HostStatus = iota
	Online
	Offline
	Unknown
)

// Just an alias to make the code more readable
type Strategy int

// The strategy of how the target was chosen
const (
	LoadStrategy       Strategy = iota // If we chose it based on load
	RoundRobinStrategy                 // Simple round robin algoritthm
	NoStrategy                         // used when there is only one backend
)

////////////////////////////////////////////////////////////////////////////////
// Multiple loggers for various verbosity levels
var (
	Debug *log.Logger // Seen with -vv
	Info  *log.Logger // Seen with -v
	Warn  *log.Logger // Always seen
	Error *log.Logger // Always seen
)

////////////////////////////////////////////////////////////////////////////////
// Variables

// Simple incremental connection ID. Eq to the # of total handled clients
var connid = uint64(0)

// Currently connected clients
var activeConn = uint64(0)

// Where to listen to. Takes Host:Port
var localAddr = flag.String("l", ":9999", "local address and port")

// Name of the cluster. @see REIGN
var cluster = flag.String("c", "hoek", "cluster to forward to")

// We should normally run this script with -vv
var verbose = flag.Bool("v", false, "display load balancer actions")
var veryverbose = flag.Bool("vv", false, "display more load balancer actions")

var version = flag.Bool("V", false, "print version and exit")

// The last array index that we dispatched a client to if we're using Round
// Robin
var RRlastID = -1

// Main function duh
func main() {

	flag.Parse()

	Debug, Info, Warn, Error = newLoggers("")

	// Cluster name check
	Hosts, ok := REIGN[*cluster]
	if !ok {
		Error.Fatalln("Unknown cluster name")
	}

	if *version {
		fmt.Printf("%s\n", VERSION)
		os.Exit(0)
	}

	// Spawn some more threads for performance
	NCPU := runtime.NumCPU()
	runtime.GOMAXPROCS(2 * NCPU)

	// Collect the target names for the log output
	targets := ""
	for _, host := range Hosts {
		targets += " " + host.Name
	}
	Info.Printf("Targets:%s\n", targets)
	if len(Hosts) == 1 {
		Info.Printf("Found only 1 host to dispatch on. Will not check if host is online when client connects.")
	}

	laddr, err := net.ResolveTCPAddr("tcp", *localAddr)
	if err != nil {
		Error.Fatalln(err.Error())
	}
	listener, err := net.ListenTCP("tcp", laddr)
	if err != nil {
		Error.Fatalln(err.Error())
	}
	Info.Printf("Listening on %v\n", *localAddr)

	// Handle stop signal from upstart or Ctrl-C
	sigterm := make(chan os.Signal, 1)
	signal.Notify(sigterm, syscall.SIGTERM)
	go func() {
		<-sigterm
		Info.Println("Received SIGTERM. Shutting down")
		os.Exit(0)
	}()

	///////////////////////////////////////////////////////////////////////////
	// Main connection handling loop
	for {
		// Blocks until a client connects
		conn, err := listener.AcceptTCP()
		if err != nil {
			Warn.Printf("Failed to accept connection '%s'\n", err)
			continue
		}
		connid++
		activeConn++

		// Have to pass in connid since go doesn't close over it.
		// google: "golang function closure"
		go func(connid uint64) {
			// Clean up & close connection. The defer makes sure this is called
			// when something goes wrong or the client disconnects.
			defer conn.Close()

			// Loggers with a prefix so we can distiguish the connection in the log
			logD, logI, logW, logE := newLoggers(fmt.Sprintf("CONN #%04d ", connid))
			logI.Printf("New client connected %s\n", conn.RemoteAddr().String())

			// If we have only 1 host we don't actually check load or online/offline status
			if len(Hosts) > 1 {
				populateClusterLoad(Hosts)
			}
			hostId, strategy, err := chooseHost(Hosts)
			if err != nil {
				// If we fail to choose any Host (maybe all are offline)
				logW.Println(err.Error())
				activeConn--
				return
			}
			host := &Hosts[hostId]
			raddr, err := net.ResolveTCPAddr("tcp", host.Name+":22")

			warnOnErr(err)

			// The main data structure that represents our two way connecton
			// to/from client/server
			p := &proxy{
				lconn:  conn,
				laddr:  laddr,
				raddr:  raddr,
				host:   host,
				erred:  false,
				errsig: make(chan bool),
				debug:  logD,
				info:   logI,
				warn:   logW,
				error:  logE,
			}
			host.DispCount++
			host.ActiveConn++
			p.printHostSummary(Hosts, strategy)
			// Blocks. Only returns when client disconnects
			p.start()
			// Once we returned from start() the client has disconnected
			activeConn--
			host.ActiveConn--
			// Debug.Printf("Currently connected clients: %d\n", activeConn)
		}(connid)
	}
}

////////////////////////////////////////////////////////////////////////////////
// Networking
////////////////////////////////////////////////////////////////////////////////

// A proxy represents a pair of connections and their state
// r(remote) is our server, l(ocal) is our client
type proxy struct {
	sentBytes     uint64
	receivedBytes uint64
	laddr, raddr  *net.TCPAddr // The host/port of target/client
	lconn, rconn  *net.TCPConn // A handle for the two TCP connections
	host          *Host        // The host we're dispatched on
	erred         bool         // Indicates if there was an error for this connection
	errsig        chan bool    // Channel that indicates that an error occured.
	debug         *log.Logger
	info          *log.Logger
	warn          *log.Logger
	error         *log.Logger
}

// Takes the proxy struct and establishes the connection. Then starts the
// routines for full duplex copying.
// Waits on the TCP connections to error and then returns. (Hence blocks)
func (p *proxy) start() {
	// connect to server which handles the client
	rconn, err := net.DialTCP("tcp", nil, p.raddr)
	if err != nil {
		p.disconnect("Remote connection failed: %s\n", err)
		return
	}
	p.rconn = rconn
	defer p.rconn.Close() // Close connection after return from this function
	// Display all ports/connections to allow fail2ban translate the ports
	p.info.Printf("Opened %s <tcp> %s <pipe> %s <tcp> %s\n",
		p.lconn.RemoteAddr().String(),
		p.lconn.LocalAddr().String(),
		p.rconn.LocalAddr().String(),
		p.rconn.RemoteAddr().String())
	// Debug.Printf("Currently connected clients: %d\n", activeConn)
	// bidirectional copy
	go p.pipe(p.lconn, p.rconn)
	go p.pipe(p.rconn, p.lconn)
	// Wait for close or some kind of error before returning.
	<-p.errsig
	p.info.Printf("Closed %s <tcp> %s <pipe> %s <tcp> %s (%d bytes sent, %d bytes received)\n",
		p.lconn.RemoteAddr().String(),
		p.lconn.LocalAddr().String(),
		p.rconn.LocalAddr().String(),
		p.rconn.RemoteAddr().String(),
		p.sentBytes,
		p.receivedBytes)
}

// Takes two existing TCP connections and copies all incoming traffic to the
// other channel. Returns only upon an error
// This function has some commented out code. This was me playing with TCP
// keepalive and the annoying missing API from go.
// It doesn't work so it's now kept simple and just disconnects after inactivity.
func (p *proxy) pipe(src, dst *net.TCPConn) {
	islocal := src == p.lconn

	// Detecting a broken/down connection in TCP is a little tricky as it turns
	// out:
	// http://tldp.org/HOWTO/TCP-Keepalive-HOWTO/usingkeepalive.html
	// $ tail /proc/sys/net/ipv4/tcp_keepalive_*
	// ==> /proc/sys/net/ipv4/tcp_keepalive_intvl <==
	// 75
	// ==> /proc/sys/net/ipv4/tcp_keepalive_probes <==
	// 9
	// ==> /proc/sys/net/ipv4/tcp_keepalive_time <==
	// 7200
	// Unfortunately GO sets both, interval and idle time :(
	// http://felixge.de/2014/08/26/tcp-keepalive-with-golang.html

	// src.SetKeepAlive(true)
	// src.SetKeepAlivePeriod(TCP_KEEP_ALIVE) // Bad don't set (read blog post above)
	// linuxEnableKeepAlive(src)

	// directional copy (16k buffer)
	buff := make([]byte, 0x3fff)
	// This loop is our main copy loop. It takes each packet and just shoves it
	// into the other side. This works for both ways
	for {
		// We will set a timeout so that we also drop clients after a while of
		// no activity.
		// Problem: This also dropps the connection even if sitting on an idle
		// shell. But who really leaves it hanging for days without any input/output?
		src.SetReadDeadline(time.Now().Add(TCP_READ_TIMEOUT))
		n, err := src.Read(buff)
		if err != nil {
			if neterr, ok := err.(net.Error); ok && neterr.Timeout() {
				// Activate TCPs keepalive now which will close the connection
				// if the client is gone
				// TODO: Doesnt work:
				// linuxEnableKeepAlive(src)
				p.disconnect("Inactive client '%s'\n", err)
				return
			} else {
				p.disconnect("Read failed '%s'\n", err)
				return
			}
		}
		b := buff[:n]
		// write out result
		n, err = dst.Write(b)
		if err != nil {
			p.disconnect("Write failed '%s'\n", err)
			return
		}
		if islocal {
			p.sentBytes += uint64(n)
		} else {
			p.receivedBytes += uint64(n)
		}
	}
}

// Not used anymore but kept for now. Trying to get keepalive in linux going
// Above in the source code is a link to a blog post. Stolen from there.
func linuxEnableKeepAlive(tcp *net.TCPConn) {
	file, err := tcp.File()
	if err == nil {
		// LINUX ONLY!!
		// If we error we just don't set these options. No harm.
		fd := int(file.Fd())
		os.NewSyscallError("setsockopt", syscall.SetsockoptInt(fd, syscall.IPPROTO_TCP,
			syscall.TCP_KEEPIDLE, TCP_KEEP_ALIVE))
		os.NewSyscallError("setsockopt", syscall.SetsockoptInt(fd, syscall.IPPROTO_TCP,
			syscall.TCP_KEEPCNT, 9)) // _probes
		os.NewSyscallError("setsockopt", syscall.SetsockoptInt(fd, syscall.IPPROTO_TCP,
			syscall.TCP_KEEPINTVL, 75)) // _intvl
	}
}

////////////////////////////////////////////////////////////////////////////////
// Load & load balance logic
////////////////////////////////////////////////////////////////////////////////
// Async queries the target machine's load all concurrently and waits for all
// of them to finish. Modifies the passes in hosts with the load info
func populateClusterLoad(hosts []Host) {
	var wg sync.WaitGroup
	for i, _ := range hosts {
		wg.Add(1)
		go queryHostLoad(&hosts[i], &wg)
	}
	// Wait for all load go queries to finish, then return
	wg.Wait()
}

// Calls the php script to obtain the load information of a target machine.
// Blocks. Changes the passed in host pointer.
func queryHostLoad(host *Host, wg *sync.WaitGroup) {
	// We can block here. We're in a go routine
	// Don't put a return into this function anywhere or you'll have a bad
	// time! You need to call wg.Done()!!!!
	// out, err := exec.Command("./get-nrpe-load.php", host.Name).Output()
	// Using timeout works for killing the php process which sometimes just hangs
	out, err := exec.Command("/usr/bin/timeout", "1", "./get-nrpe-load.php", host.Name).Output()
	if err != nil {
		host.Status = Offline
	} else {
		outS := string(out[:])
		if outS == "ONLINE" {
			// We couldn't obtain a load
			host.Status = Online
		} else if outS == "OFFLINE" {
			host.Status = Offline
		} else if load, ok := strconv.ParseFloat(outS, 32); ok == nil {
			host.Status = OnlineWithLoad
			host.Load1m = load
		} else {
			host.Status = Offline // This should never happen
		}
	}
	wg.Done()
}

// Prints the current usage for the given hosts
func (p *proxy) printHostSummary(hosts []Host, strategy Strategy) {
	strategyStr := ""
	switch strategy {
	case RoundRobinStrategy:
		strategyStr = "RoundRobin"
	case LoadStrategy:
		strategyStr = "LoadBased"
	case NoStrategy:
		strategyStr = "OnlyOne"
	}
	for _, host := range hosts {
		chosen := ""
		if p.host.Name == host.Name {
			chosen = " (CHOSEN, " + strategyStr + ")"
		}
		switch host.Status {
		case Unknown:
			// Can happen if we only have one target system. We don't query it then
			p.warn.Printf("%s (Active %d, All-time %d) Unknown.%s\n", host.Name, host.ActiveConn, host.DispCount, chosen)
		case Offline:
			p.warn.Printf("%s (Active %d, All-time %d) Offline.%s\n", host.Name, host.ActiveConn, host.DispCount, chosen)
		case OnlineWithLoad:
			p.info.Printf("%s (Active %d, All-time %d) Load %.1f of %.1f%s\n", host.Name, host.ActiveConn, host.DispCount, host.Load1m, host.MaxLoad, chosen)
		case Online:
			p.info.Printf("%s (Active %d, All-time %d) Online no load info%s\n", host.Name, host.ActiveConn, host.DispCount, chosen)
		}
	}
}

// Given the host poplated with load etc we choose one.
// Strategy is waterfilling. MaxLoad - Load1m
// If no load information can be obtained it is falling back to round robin
// The index of the used host is returned as well as the strategy
func chooseHost(hosts []Host) (int, Strategy, error) {
	if len(hosts) == 1 {
		return 0, NoStrategy, nil
	}
	haveLoadInfo := false
	haveOnlineHost := false
	for _, host := range hosts {
		switch host.Status {
		case OnlineWithLoad:
			haveLoadInfo = true
		case Online:
			haveOnlineHost = true
		}
	}
	if !haveOnlineHost && !haveLoadInfo {
		return -1, NoStrategy, errors.New("Every target host was offline")
	}
	// Note some of this code is optimized for easy comprehension. Not performance
	if !haveLoadInfo {
		// Round Robin
		// First find the very first online host
		return roundRobinStrategy(hosts)
	} else {
		return lowestLoadStrategy(hosts)
	}
}

// Given a bunch of hosts it will return the index of the server with the
// lowest load. Or if none were online it will return an error.
func lowestLoadStrategy(hosts []Host) (int, Strategy, error) {
	maxUnusedLoad := -10000.0
	index := -1
	for i, host := range hosts {
		if host.Status == OnlineWithLoad {
			unusedLoad := host.MaxLoad - host.Load1m // might be neg
			if unusedLoad > maxUnusedLoad {
				maxUnusedLoad = unusedLoad
				index = i
			}
		}
	}
	if index == -1 {
		// Only if there are race conditions
		return -1, NoStrategy, errors.New("Every target host was offline")
	} else {
		return index, LoadStrategy, nil
	}
}

// Given some hosts returnes the next host candidate for a round robin alg.
func roundRobinStrategy(hosts []Host) (int, Strategy, error) {
	firstOnline := -1
	// Find the first online server that is available
	for i, host := range hosts {
		if host.Status == Online {
			firstOnline = i
			break
		}
	}
	// Find the server next in line after the last used one and return int
	for i, host := range hosts {
		if i > RRlastID && host.Status == Online {
			RRlastID = i
			return i, RoundRobinStrategy, nil
		}
	}
	// We only get here if we have to start over since there was no next one
	if firstOnline != -1 {
		RRlastID = firstOnline
		return firstOnline, RoundRobinStrategy, nil
	} else {
		// All hosts are offline :(. This should be unreachable except for race conditions
		return -1, NoStrategy, errors.New("Every target host was offline")
	}
}

// Sents a flag to terminate the connection and sends a signal to the channel
// so that the copy go routine can terminate
func (p *proxy) disconnect(s string, err error) {
	if p.erred {
		return
	}
	if err != io.EOF {
		p.warn.Printf(s, err)
	}
	p.errsig <- true
	p.erred = true
}

////////////////////////////////////////////////////////////////////////////////
// Helper functions & logging
////////////////////////////////////////////////////////////////////////////////
// Creates some loggers depending on the given verbosity command line arguments
func newLoggers(prefix string) (debugL, infoL, warnL, errorL *log.Logger) {
	if *veryverbose {
		*verbose = true
	}
	debugH := ioutil.Discard
	infoH := ioutil.Discard
	if *verbose {
		infoH = os.Stdout
	}
	if *veryverbose {
		debugH = os.Stdout
	}
	debugL = log.New(debugH, "DEBU: "+prefix, log.Ldate|log.Lmicroseconds)
	infoL = log.New(infoH, "INFO: "+prefix, log.Ldate|log.Lmicroseconds)
	warnL = log.New(os.Stdout, "WARN: "+prefix, log.Ldate|log.Lmicroseconds)
	errorL = log.New(os.Stdout, "ERRO: "+prefix, log.Ldate|log.Lmicroseconds)
	return
}

func warnOnErr(err error) {
	if err != nil {
		Warn.Println(err.Error())
	}
}

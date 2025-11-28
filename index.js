#!/usr/bin/env node

const Cap = require('cap').Cap;
const decoders = require('cap').decoders;
const PROTOCOL = decoders.PROTOCOL;
const fs = require('fs');
const path = require('path');

class PacketCapture {
  constructor(options = {}) {
    this.interface = options.interface || this.getDefaultInterface();
    this.filter = options.filter || '';
    this.outputFile = options.outputFile || 'packets.csv';
    this.maxPackets = options.maxPackets || 0; // 0 = unlimited
    this.packetCount = 0;
    this.cap = new Cap();
    this.buffer = Buffer.alloc(65535);
    this.csvStream = null;
    this.previousTimestamp = null;
  }

  getDefaultInterface() {
    const devices = Cap.deviceList();
    if (devices.length === 0) {
      throw new Error('No network interfaces found');
    }

    // Try to find a non-loopback interface
    const nonLoopback = devices.find(dev => dev.name !== 'lo' && dev.name !== 'lo0');
    return nonLoopback ? nonLoopback.name : devices[0].name;
  }

  initializeCSV() {
    // Create CSV file with headers
    const headers = 'Timestamp,Delta (ms),Protocol,Source IP,Source Port,Destination IP,Destination Port,Length,Info\n';
    fs.writeFileSync(this.outputFile, headers);
    this.csvStream = fs.createWriteStream(this.outputFile, { flags: 'a' });
    console.log(`CSV output file: ${this.outputFile}`);
  }

  parsePacket(rawPacket) {
    const ret = decoders.Ethernet(rawPacket);

    if (ret.info.type === PROTOCOL.ETHERNET.IPV4 || ret.info.type === PROTOCOL.ETHERNET.IPV6) {
      const isIPv4 = ret.info.type === PROTOCOL.ETHERNET.IPV4;
      const datagramInfo = isIPv4
        ? decoders.IPV4(rawPacket, ret.offset)
        : decoders.IPV6(rawPacket, ret.offset);
      ret.offset = datagramInfo.offset;

      const packetData = {
        timestamp: new Date().toISOString(),
        protocol: isIPv4 ? 'IPv4' : 'IPv6',
        srcIP: datagramInfo.info.srcaddr,
        srcPort: '',
        dstIP: datagramInfo.info.dstaddr,
        dstPort: '',
        length: rawPacket.length,
        info: ''
      };

      // Parse TCP
      if (datagramInfo.info.protocol === PROTOCOL.IP.TCP) {
        const tcpInfo = decoders.TCP(rawPacket, ret.offset);
        packetData.protocol = 'TCP';
        packetData.srcPort = tcpInfo.info.srcport;
        packetData.dstPort = tcpInfo.info.dstport;
        packetData.info = `Flags: ${this.getTCPFlags(tcpInfo.info.flags)}`;
      }
      // Parse UDP
      else if (datagramInfo.info.protocol === PROTOCOL.IP.UDP) {
        const udpInfo = decoders.UDP(rawPacket, ret.offset);
        packetData.protocol = 'UDP';
        packetData.srcPort = udpInfo.info.srcport;
        packetData.dstPort = udpInfo.info.dstport;
        packetData.info = `UDP packet`;
      }
      // Parse ICMP
      else if (datagramInfo.info.protocol === PROTOCOL.IP.ICMP) {
        packetData.protocol = 'ICMP';
        packetData.info = 'ICMP packet';
      }
      else {
        packetData.protocol = `IP Protocol ${datagramInfo.info.protocol}`;
        packetData.info = 'Other IP protocol';
      }

      return packetData;
    }
    else if (ret.info.type === PROTOCOL.ETHERNET.ARP) {
      const arpInfo = decoders.ARP(rawPacket, ret.offset);
      return {
        timestamp: new Date().toISOString(),
        protocol: 'ARP',
        srcIP: arpInfo.info.srcaddr,
        srcPort: '',
        dstIP: arpInfo.info.dstaddr,
        dstPort: '',
        length: rawPacket.length,
        info: `ARP ${arpInfo.info.opcode === 1 ? 'Request' : 'Reply'}`
      };
    }

    return null;
  }

  getTCPFlags(flags) {
    const flagNames = [];
    if (flags & 0x01) flagNames.push('FIN');
    if (flags & 0x02) flagNames.push('SYN');
    if (flags & 0x04) flagNames.push('RST');
    if (flags & 0x08) flagNames.push('PSH');
    if (flags & 0x10) flagNames.push('ACK');
    if (flags & 0x20) flagNames.push('URG');
    return flagNames.join(',') || 'NONE';
  }

  escapeCSV(value) {
    if (value === null || value === undefined) return '';
    const str = String(value);
    if (str.includes(',') || str.includes('"') || str.includes('\n')) {
      return `"${str.replace(/"/g, '""')}"`;
    }
    return str;
  }

  writePacketToCSV(packetData) {
    const currentTime = new Date(packetData.timestamp);
    let delta = 0;

    if (this.previousTimestamp !== null) {
      delta = Math.round(currentTime - this.previousTimestamp);
    }

    this.previousTimestamp = currentTime;

    const row = [
      this.escapeCSV(packetData.timestamp),
      this.escapeCSV(delta),
      this.escapeCSV(packetData.protocol),
      this.escapeCSV(packetData.srcIP),
      this.escapeCSV(packetData.srcPort),
      this.escapeCSV(packetData.dstIP),
      this.escapeCSV(packetData.dstPort),
      this.escapeCSV(packetData.length),
      this.escapeCSV(packetData.info)
    ].join(',') + '\n';

    this.csvStream.write(row);
  }

  start() {
    try {
      console.log('Available network interfaces:');
      Cap.deviceList().forEach(dev => {
        console.log(`  - ${dev.name}${dev.description ? ': ' + dev.description : ''}`);
      });

      console.log(`\nStarting packet capture on interface: ${this.interface}`);
      if (this.filter) {
        console.log(`Filter: ${this.filter}`);
      }
      if (this.maxPackets > 0) {
        console.log(`Capturing up to ${this.maxPackets} packets`);
      } else {
        console.log('Capturing packets (Ctrl+C to stop)');
      }

      this.initializeCSV();

      const linkType = this.cap.open(this.interface, this.filter, 10 * 1024 * 1024, this.buffer);

      this.cap.setMinBytes && this.cap.setMinBytes(0);

      this.cap.on('packet', (nbytes, trunc) => {
        if (this.maxPackets > 0 && this.packetCount >= this.maxPackets) {
          this.stop();
          return;
        }

        const rawPacket = this.buffer.slice(0, nbytes);
        const packetData = this.parsePacket(rawPacket);

        if (packetData) {
          this.packetCount++;
          this.writePacketToCSV(packetData);

          // Print packet summary to console
          console.log(`[${this.packetCount}] ${packetData.protocol}: ${packetData.srcIP}:${packetData.srcPort} -> ${packetData.dstIP}:${packetData.dstPort}`);

          if (this.maxPackets > 0 && this.packetCount >= this.maxPackets) {
            console.log(`\nReached maximum packet count (${this.maxPackets})`);
            this.stop();
          }
        }
      });

      // Handle graceful shutdown
      process.on('SIGINT', () => {
        console.log('\n\nStopping packet capture...');
        this.stop();
      });

      process.on('SIGTERM', () => {
        this.stop();
      });

    } catch (err) {
      console.error('Error starting packet capture:', err.message);
      if (err.message.includes('Permission denied')) {
        console.error('Hint: Try running with sudo (e.g., sudo node index.js)');
      }
      process.exit(1);
    }
  }

  stop() {
    if (this.csvStream) {
      this.csvStream.end();
    }
    this.cap.close();
    console.log(`\nCapture complete. Total packets captured: ${this.packetCount}`);
    console.log(`Results saved to: ${this.outputFile}`);
    process.exit(0);
  }
}

// Parse command line arguments
function parseArgs() {
  const args = process.argv.slice(2);
  const options = {
    interface: null,
    filter: '',
    outputFile: 'packets.csv',
    maxPackets: 0
  };

  for (let i = 0; i < args.length; i++) {
    switch (args[i]) {
      case '-i':
      case '--interface':
        options.interface = args[++i];
        break;
      case '-f':
      case '--filter':
        options.filter = args[++i];
        break;
      case '-o':
      case '--output':
        options.outputFile = args[++i];
        break;
      case '-n':
      case '--count':
        options.maxPackets = parseInt(args[++i], 10);
        break;
      case '-h':
      case '--help':
        console.log(`
Usage: node index.js [options]

Options:
  -i, --interface <name>    Network interface to capture on
  -f, --filter <filter>     BPF filter (e.g., "tcp port 80")
  -o, --output <file>       Output CSV file (default: packets.csv)
  -n, --count <number>      Number of packets to capture (default: unlimited)
  -h, --help                Show this help message

Examples:
  sudo node index.js
  sudo node index.js -i eth0 -n 100
  sudo node index.js -f "tcp port 443" -o https_packets.csv
  sudo node index.js -i wlan0 -f "host 192.168.1.1" -n 50
`);
        process.exit(0);
        break;
    }
  }

  return options;
}

// Main execution
if (require.main === module) {
  const options = parseArgs();
  const capture = new PacketCapture(options);
  capture.start();
}

module.exports = PacketCapture;

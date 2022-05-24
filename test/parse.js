const MHYbuf = require('../util/MHYbuf')
const MT19937_64 = require("../util/mt64");
const pcapp = require('pcap-parser')
const kcp = require("node-kcp");
const fs = require("fs");
const protobuf = require("protobufjs");

const args = require('yargs/yargs')(process.argv.slice(2))
    .completion()
    .argv

const pcap_filename = args._[0];
const DIR_SERVER = 0;
const DIR_CLIENT = 1;
const PACKET_GetPlayerTokenRsp = MHYbuf.getPacketIDByProtoName('GetPlayerTokenRsp');
const PACKET_UnionCmdNotify = MHYbuf.getPacketIDByProtoName('UnionCmdNotify');
const MHYKeys = require('../data/MHYkeys.json');
for (let key in MHYKeys) {
    MHYKeys[key] = Buffer.from(MHYKeys[key], 'base64');
}
const packetIds = require('../data/packetIds.json')
let initialKey;
let yuankey;
var serverBound = {};
var clientBound = {};

function print_buf_(buf) {
    let bytes = [], len = buf.byteLength
    for (let i = 0; i < len; ++i) {
        if (i && i % 16 == 0) {
            console.log(bytes.join(' '))
            bytes = []
        }
        if (i % 16 == 4 || i % 16 == 8 || i % 16 == 12) {
            bytes.push('')
        }
        bytes.push(buf.readUInt8(i).toString(16).toUpperCase().padStart(2, '0'))
    }
    if (bytes.length)
        console.log(bytes.join(' '))

}

function print_buf(buf, title, max_len) {
    let bytes = [], len = buf.byteLength
    console.log((title || 'untitled buffer') + ` (${buf.byteLength} bytes)`)
    if (max_len < len) len = max_len
    for (let i = 0; i < len; ++i) {
        if (i && i % 16 == 0) {
            console.log(bytes.join(' '))
            bytes = []
            // if (i / 16 == 10 && i + 1 < buf.byteLength) {
            //     console.log('...')
            //     return
            // }
        }
        if (i % 16 == 4 || i % 16 == 8 || i % 16 == 12) {
            bytes.push('')
        }
        bytes.push(buf.readUInt8(i).toString(16).toUpperCase().padStart(2, '0'))
    }
    if (bytes.length)
        console.log(bytes.join(' '))
    if (len < buf.byteLength) {
        console.log(`... (${buf.byteLength - len} bytes omitted)`)
    }
}

async function dataToProtobuffer(data, packetID) {
    var protoName = MHYbuf.getProtoNameByPacketID(packetID);

    if (protoName == "None") {
        return protoName;
    }

    const root = await protobuf.load("./data/proto/" + protoName + ".proto");
    const testMessage = root.lookup(protoName);
    const message = testMessage.decode(data);
    return message;
}

async function processMHYPacket(packet) {
    let {
        crypt,
        uncrypt,
        ip,
        overrideKey
    } = packet;
    if (uncrypt) return [uncrypt];
    if (!crypt) return console.warn("Empty data received.");

    let packetSource = (ip.port == 22101 || ip.port == 22102) ? DIR_SERVER : DIR_CLIENT;
    if (crypt.byteLength <= 20) {
        yuankey = undefined;
        initialKey = undefined;
        serverBound = {};
        clientBound = {};
        switch (crypt.readInt32BE(0)) {
            case 0xFF:
                console.warn("Handshake", "Connected");
                break;
            case 404:
                console.warn("Handshake", "Disconnected"); //red
                break;
            default:
                // console.warn("UNKNOWN HANDSHAKE", crypt.readInt32BE(0));
                break;
        }
        return;
    }

    let KCPContextMap;
    if (packetSource == DIR_SERVER) {
        KCPContextMap = serverBound;
    } else {
        KCPContextMap = clientBound;
    }

    let peerID = ip.address + '_' + ip.port + '_' + crypt.readUInt32LE(0).toString(16);
    if (!KCPContextMap[peerID]) {
        KCPContextMap[peerID] = new kcp.KCP(crypt.readUInt32LE(0), ip);
        // KCPContextMap[peerID].nodelay(1, 1000, 2, 0)
        console.warn('KCP', 'Instance created: ' + peerID);
    }

    let kcpobj = KCPContextMap[peerID];
    // print_buf(crypt, 'raw data', 8)
    kcpobj.input(await MHYbuf.reformatKcpPacket(crypt))
    var hrTime = process.hrtime();
    kcpobj.update(hrTime[0] * 1000000 + hrTime[1] / 1000);
    kcpobj.wndsize(1024, 1024);

    // let packets = [];
    let recv;
    do {
        recv = kcpobj.recv();
        if (!recv) break;
        if (!initialKey) {
            initialKey = MHYKeys[recv.readUInt16BE(0) ^ 0x4567];
        }
        let keyBuffer = overrideKey || yuankey || initialKey;
        MHYbuf.xorData(recv, keyBuffer);

        let packetID = recv.readUInt16BE(2);

        // console.log('packet id:', packetID)
        // let proto_buf = MHYbuf.parsePacketData(recv)
        // console.log(`protobuf data (${proto_buf.byteLength} bytes):`)
        // print_buf(proto_buf)
        if (packetID == 4061) {
            // let proto_buf = MHYbuf.parsePacketData(recv)
            // let proto = await MHYbuf.dataToProtobuffer(proto_buf, "GetFriendShowAvatarInfoReq")
            // let uid = proto.uid
            // let time = String(Math.floor(hrTime[1] / 1000)).padStart(6, '0')
            // console.log('uid:', uid)
            // print_buf(crypt, "4061 raw")
            // fs.writeFileSync(`4061-raw-${uid}-${time}.bin`, crypt)
            // print_buf(recv, "4061 recv")
            // fs.writeFileSync(`4061-recv-${uid}-${time}.bin`, recv)
            // print_buf(proto_buf, "4061 proto")
            // fs.writeFileSync(`4061-proto-${uid}-${time}.bin`, proto_buf)
        } else {
            // print_buf(recv, `${packetID} recv`)
        }
        // console.log(`${packetID} recv (${recv.byteLength} bytes)`)
        let head_len = recv.readInt8(5)
        // print_buf_(recv.slice(0, 10))

        /* print csv line */
        let line = []
        if (packetSource == DIR_CLIENT) {
            line.push('client')
        } else {
            line.push('server')
        }
        line.push(packetID)
        line.push(packetIds[packetID] || 'NOT_FOUND')
        for (let i = 10; i < 10 + head_len; ++i) {
            if (i == 12) {
                for (let j = 0; j < 12 - head_len; ++j) {
                    line.push('')
                }
            }
            line.push(recv.readUInt8(i).toString(16).toUpperCase().padStart(2, '0'))
        }
        while (line.length < 15) line.push('')
        let proto_buf = MHYbuf.parsePacketData(recv)
        line.push(proto_buf.length)
        if (proto_buf.length) {
            let msg = ''
            try {
                var proto = await dataToProtobuffer(proto_buf, packetID)
                msg = JSON.stringify(proto)
                if (msg.length > 50)
                    msg = msg.slice(0, 50) + '...'
            } catch (e) {
                msg = 'ERR: ' + e.message
            }
            msg = msg.replace(/"/g, "'")
            line.push(`"${msg}"`)
        } else {
            line.push('')
        }
        console.log(line.join(','))

        if (packetID == PACKET_GetPlayerTokenRsp) {
            var proto = await MHYbuf.dataToProtobuffer(MHYbuf.parsePacketData(recv), "GetPlayerTokenRsp")
            console.warn('key seed', proto.secretKeySeed.toString())
            let initgen = new MT19937_64();
            initgen.seed(BigInt(proto.secretKeySeed));
            let generator = new MT19937_64();
            generator.seed(initgen.int64());
            generator.int64();
            let key = Buffer.alloc(4096);
            for (let i = 0; i < 4096; i += 8) {
                let val = generator.int64();
                key.writeBigUInt64BE(val, i)
            }
            yuankey = key;
            // print_buf(yuankey, 'override key', 32)
        }
        // packets.push(recv);
    } while (recv);
    hrTime = process.hrtime();
    kcpobj.update(hrTime[0] * 1000000 + hrTime[1] / 1000)
    // return packets;
}

function read_pcap(filename) {
    const stream = fs.createReadStream(filename)
    var parser = pcapp.parse(stream);
    const packetQueue = [];

    parser.on('packet', packet => {
        if (packet.data.readInt16LE(12) === 8)
            packet.data = packet.data.slice(14);
        let udp = MHYbuf.read_pcap_udp_header(packet.data);
        let ip = MHYbuf.read_pcap_ipv4_header(packet.data);
        if (udp.port_src !== 22101 &&
            udp.port_src !== 22102 &&
            udp.port_dst !== 22101 &&
            udp.port_dst !== 22102) return
        packetQueue.push({
            crypt: packet.data.slice(28),
            ip: {
                address: ip.src_addr,
                address_dst: ip.dst_addr,
                port: udp.port_src,
                port_dst: udp.port_dst
            },
            time: packet.header.timestampSeconds * 1000 + Math.floor(packet.header.timestampMicroseconds / 1000)
        })
    });
    parser.on('end', async () => {
        let line = ['dir', 'pid', 'pname']
        for (let i = 1; i <= 12; ++i) {
            line.push('h' + i.toString().padStart(2, '0'))
        }
        line = line.concat(['len', 'msg'])
        console.log(line.join(','))
        for (let packet of packetQueue) {
            await processMHYPacket(packet)
        }
    });
}

read_pcap(pcap_filename)
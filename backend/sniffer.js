const proxy = require('udp-proxy')
const MHYbuf = require("../util/MHYbuf");
const kcp = require("node-kcp");
const fs = require("fs");
const pcapp = require('pcap-parser');
// const SQLiteCrud = require('sqlite3-promisify');
const DelimiterStream = require('delimiter-stream');
const util = require('util');
const path = require('path');
const execFile = util.promisify(require('child_process').execFile);
const udpPacket = require('udp-packet');
const ipPacket = require('ip-packet')
const {
    WSMessage
} = require("../util/classes");
const log = new (require("../util/log"))('Sniffer', 'blueBright');
const chalk = require('chalk');
let Session = {
    //filename
    //proxy
}
const frontend = require('./frontend-server')
const MT19937_64 = require("../util/mt64");
// async function kek() {
// 	const keysDB = new SQLiteCrud('./data/keys2.db');
// 	let r = {};
// 	let rows = await keysDB.all('SELECT * FROM keys');

// 		rows.forEach(row => {
// 			r[row.first_bytes] = Buffer.from(row.key_buffer).toString('base64');
// 		})
// 		console.log(JSON.stringify(r));
// }
// kek();
const packetQueue = [];
const DIR_SERVER = 0;
const DIR_CLIENT = 1;
const GCAP_DELIM = '█▄█\n';
const GCAP_DIR = path.join('.', 'captures')
const PACKET_GetPlayerTokenRsp = MHYbuf.getPacketIDByProtoName('GetPlayerTokenRsp');
const PACKET_UnionCmdNotify = MHYbuf.getPacketIDByProtoName('UnionCmdNotify');

let packetQueueSize = 0;
let unknownPackets = 0,
    packetOrderCount = 0;
let MHYKeys = require('../data/MHYkeys.json');
const config = require('../config');
const { hrtime } = require('process');
for (let key in MHYKeys) {
    MHYKeys[key] = Buffer.from(MHYKeys[key], 'base64');
}
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

async function processMHYPacket(packet) {
    let {
        crypt,
        uncrypt,
        ip,
        overrideKey
    } = packet;
    if (uncrypt) return [uncrypt];
    if (!crypt) return log.warn("Empty data received.");

    let packetSource = (ip.port == 22101 || ip.port == 22102) ? DIR_SERVER : DIR_CLIENT;
    if (crypt.byteLength <= 20) {
        yuankey = undefined;
        initialKey = undefined;
        serverBound = {};
        clientBound = {};
        switch (crypt.readInt32BE(0)) {
            case 0xFF:
                log.log("Handshake", "Connected");
                frontend.queuePacket({
                    source: packetSource,
                    packetID: 'HND',
                    protoName: 'Handshake',
                    object: 'Hamdshanke pls.'
                })
                break;
            case 404:
                log.log("Handshake", "Disconnected"); //red
                break;
            default:
                frontend.queuePacket({
                    source: packetSource,
                    packetID: 'HND',
                    protoName: 'Handshake',
                    object: 'Hamdshanke estamblished.'
                })
                // log.warn("UNKNOWN HANDSHAKE", crypt.readInt32BE(0));
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
        log.log('KCP', 'Instance created: ' + peerID);
    }

    let kcpobj = KCPContextMap[peerID];
    // print_buf(crypt, 'raw data', 8)
    kcpobj.input(await MHYbuf.reformatKcpPacket(crypt))
    var hrTime = process.hrtime();
    kcpobj.update(hrTime[0] * 1000000 + hrTime[1] / 1000);
    kcpobj.wndsize(1024, 1024);

    let packets = [];
    let recv;
    do {
        recv = kcpobj.recv();
        if (!recv) break;
        if (!initialKey) {
            initialKey = MHYKeys[recv.readUInt16BE(0) ^ 0x4567];
        }
        let keyBuffer = overrideKey || yuankey || initialKey;
        // let temp = recv.slice()
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
        let line = []
        if (packetSource == DIR_CLIENT) {
            line.push('client')
        } else {
            line.push('server')
        }
        line.push(packetID)
        for (let i = 10; i < 10 + head_len; ++i) {
            if (i == 12) {
                for (let j = 0; j < 12 - head_len; ++j) {
                    line.push('')
                }
            }
            line.push(recv.readUInt8(i).toString(16).toUpperCase().padStart(2, '0'))
        }
        console.log(line.join(','))
        // print_buf_(recv.slice(10, 10 + head_len))
        // print_buf_(recv.slice(10 + head_len, recv.byteLength - 2))
        // print_buf_(recv.slice(recv.byteLength - 2))

        if (packetID == PACKET_GetPlayerTokenRsp) {
            var proto = await MHYbuf.dataToProtobuffer(MHYbuf.parsePacketData(recv), "GetPlayerTokenRsp")
            log.debug(proto.secretKeySeed.toString())
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
        packets.push(recv);
    } while (recv);
    hrTime = process.hrtime();
    kcpobj.update(hrTime[0] * 1000000 + hrTime[1] / 1000)
    return packets;
}

function getInfoCharacter(packetName, dir) {
    if (!isNaN(+packetName)) return ' X ';
    if (packetName.includes('Rsp')) return chalk.yellow('<--');
    if (packetName.includes('Req')) return chalk.cyan('-->');
    if (packetName.includes('Notify') && !dir) return chalk.yellowBright('<-i');
    if (packetName.includes('Notify') && dir) return chalk.cyanBright('i->');
}

function logPacket(packetSource, packetID, protoName, o, union, last) {
    return;
    let s = '';
    if (union)
        if (last)
            s += ('      └─');
        else
            s += ('      ├─');
    s += union ? '' : new Date().toLocaleTimeString();
    s += packetSource ? chalk.cyan(' [CLIENT] ') : chalk.yellow(' [SERVER] ');
    s += `${('' + packetID).padEnd(6)}${getInfoCharacter(protoName, packetSource)}   ${('' + (protoName || '')).padEnd(20)}`;
    log.plain(s);
    log.trail(JSON.stringify(o.object) || '');

    if (last) log.log();
}

async function decodePacketProto(packet, ip) {
    let packetID = packet.readUInt16BE(2);
    let protoName = MHYbuf.getProtoNameByPacketID(packetID);
    let { ignoredProtos } = require('../config');
    if (ignoredProtos.includes(protoName)) return;

    let o = {};
    if (packetID != parseInt(protoName)) {
        let object = await MHYbuf.dataToProtobuffer(MHYbuf.parsePacketData(packet), packetID);
        o = {
            packetID,
            protoName,
            object: object,
            packet: MHYbuf.parsePacketData(packet).toString('base64')
        }
    }
    if (packetID == protoName) {
        o = {
            packetID,
            protoName,
            object: null,
            missing: true,
            packet: MHYbuf.parsePacketData(packet).toString('base64')
        }
    }
    let packetSource = (ip.port == 22101 || ip.port == 22102) ? DIR_SERVER : DIR_CLIENT;
    logPacket(packetSource, packetID, protoName, o);
    // if(o.object && o.object.scData) console.log(o.object.scData.toString('base64'))
    if (packetID == PACKET_UnionCmdNotify) {
        var commands = [];
        for (var i = 0; i < o.object.cmdList.length; i++) {
            let { messageId, body } = o.object.cmdList[i];
            let protoName = MHYbuf.getProtoNameByPacketID(messageId);
            let nested = await MHYbuf.dataToProtobuffer(body, messageId);
            commands.push({
                protoName,
                packetID: messageId,
                object: nested
            })
            logPacket(packetSource, messageId, protoName, commands[commands.length - 1], true, i == o.object.cmdList.length - 1);
        }
        o.object = {}
        o.object.cmdList = commands;
    }
    if (o) o.source = packetSource;
    return o;
}



function joinBuffers(buffers, delimiter = ' ') {
    let d = Buffer.from(delimiter);
    return buffers.reduce((prev, b) => Buffer.concat([prev, d, b]));
}
function delay(t) { return new Promise(resolve => setTimeout(resolve, t)) };

function queuePacket(packet) {
    packetQueue.push(packet);
    packetQueueSize++;
}


var proxyIP = '47.103.31.140';
var proxyPort = 22101;
async function execute() {
    async function loop() {
        if (!packetQueueSize) return setTimeout(loop, 32);
        let decryptedDatagram;
        let packetObject;
        let count = 0;
        while (packetQueue.length) {
            let packet = packetQueue.shift();
            packetQueueSize--;

            if (packet.ip.port !== 22101 &&
                packet.ip.port !== 22102 &&
                packet.ip.port_dst !== 22101 &&
                packet.ip.port_dst !== 22102) continue;
            // await delay(20)
            let packets = await processMHYPacket(packet);
            if (!packets) continue;
            for (var i = 0; i < packets.length; i++) {
                let decryptedDatagram = packets[i];
                // log.log(packet.crypt.slice(0,40).toString('hex'));
                if (Session.datagrams) {
                    let datagram;
                    if (packet.ip.port === 22101 || packet.ip.port === 22102) {
                        datagram = Buffer.concat([Buffer.from([0]), decryptedDatagram])
                    } else {
                        datagram = Buffer.concat([Buffer.from([1]), decryptedDatagram])
                    }
                    Session.datagrams.push(datagram);
                };
                packetObject = await decodePacketProto(decryptedDatagram, packet.ip);
                // console.log.log(JSON.stringify(packetObject));
                if (packetObject) {
                    packetObject.time = packet.time;
                    frontend.queuePacket(packetObject);
                    dumpPacketObj(packetObject, count)
                    count++;
                }
            }
        }
        if (Session.fileHandle && Session.datagrams && Session.datagrams.length > 0) {
            await Session.fileHandle.appendFile(Buffer.concat([joinBuffers(Session.datagrams, GCAP_DELIM), Buffer.from(GCAP_DELIM)]));
            Session.written = (Session.written || 0) + 1;
            Session.datagrams = [];
        }
        setImmediate(loop);
    }
    loop();
}

let namesToDump = config.ProtosToDump;
async function dumpPacketObj(obj, count) {
    let name = obj.protoName
    let data = obj.object


    ///yeah idk why i made this async tbf 


    if (!config.dumpAll) return;
    // let namesToDump = []

    if (namesToDump && namesToDump.includes(name)) {
        if (!fs.existsSync("./Bins")) {
            fs.mkdirSync("./Bins")
        }

        fs.writeFileSync(`./Bins/${count}_${name}.json`, JSON.stringify(data, null, 4))
        if (name == 'PlayerStoreNotify') {
            const goodTrans = require('../plugins/good-transform')
            const good = goodTrans.PlayerStoreNotify(data)
            fs.writeFileSync(`./Bins/good.json`, JSON.stringify(good))
        }

        count++;
    }
}

async function pcap(file) {
    const { Readable } = require('stream');
    const stream = Readable.from(Buffer.from(file, 'base64'));
    var parser = pcapp.parse(stream);
    parser.on('packet', packet => {
        if (packet.data.readInt16LE(12) === 8)
            packet.data = packet.data.slice(14);
        let udp = MHYbuf.read_pcap_udp_header(packet.data);
        let ip = MHYbuf.read_pcap_ipv4_header(packet.data);

        queuePacket({
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
        log.log('Parse finished.')
    });
}

async function gcap(file) {
    // var fs = require('fs');
    var linestream = new DelimiterStream({
        delimiter: GCAP_DELIM
    });
    // var input = fs.createReadStream(file);
    const { Readable } = require('stream');
    const stream = Readable.from(Buffer.from(file, 'base64'));
    // file = file.split(GCAP_DELIM);
    linestream.on('data', packet => {
        // console.log.log(packet)
        ip = {};
        if (packet.readInt8(0) == 1) {
            ip.port_dst = 22101
            ip.port = null
        } else {
            ip.port = 22101
            ip.port_dst = null
        }
        queuePacket({
            uncrypt: packet.slice(1),
            ip
        })
    });
    stream.pipe(linestream);
    // stream.on('end', () => {
    // 	yuankey = undefined;
    // })
}

const INTERCEPT = false;

function proxyMiddleware(dir, msg, sender, peer, next) {
    if (!INTERCEPT) next(msg, sender, peer);
}

async function startProxySession(filename, ip, port) {
    Session = {};
    if (!filename) filename = new Date().toISOString().replace('T', '_').replace(/:/g, '-').split('.')[0] + '.gcap';
    Session.filename = path.resolve(path.join(GCAP_DIR, filename));

    Session.fileHandle = await fs.promises.open(Session.filename, 'w');
    Session.datagrams = [];
    let opt = {
        address: ip || proxyIP, // America: 47.90.134.247, Europe: 47.245.143.151
        port: port || proxyPort,
        localaddress: '127.0.0.1',
        localport: port || proxyPort,
        middleware: {
            message: (msg, sender, next) => proxyMiddleware(1, msg, sender, undefined, next),
            proxyMsg: (msg, sender, peer, next) => proxyMiddleware(0, msg, sender, peer, next)
        }
    }
    Session.proxy = proxy.createServer(opt);

    Session.proxy.on('listening', (details) => {
        log.start("UDP", 'Proxy server on', chalk.yellowBright(`${details.server.address}:${details.server.port}`));
        log.start("UDP", 'Traffic forward to', chalk.yellowBright(`${details.target.address}:${details.target.port}`));
    });

    Session.proxy.on('bound', (details) => {
        log.log('UDP', `Proxy bound to ${details.route.address}:${details.route.port}`);
        log.log('UDP', `Peer bound to ${details.peer.address}:${details.peer.port}`);
    });

    // 'message' is emitted when the server gets a message
    Session.proxy.on('message', (packet, ip) => {
        log.log('message')
        ip.address_dst = opt.address;
        ip.port_dst = opt.port;
        queuePacket({
            crypt: packet,
            ip: ip
        })
    });

    Session.proxy.on('proxyMsg', (packet, ip, peer) => {
        ip.address_dst = peer.address;
        ip.port_dst = peer.port;
        queuePacket({
            crypt: packet,
            ip: ip
        })
    });
}

async function stopProxySession() {
    if (Session.proxy) {
        Session.proxy.close();
        log.stop("UDP", 'proxy stopped')
    }
    if (Session.fileHandle) await Session.fileHandle.close();
    if (!Session.written && Session.filename) fs.unlinkSync(Session.filename);
    Session = {};
}

function getSessionStatus() {
    return !!Session.proxy;
}

async function updateProxyIP(ip, port) {
    if (Session.proxy && proxyIP !== ip || Session.proxy && proxyPort !== port) {
        log.refresh('Relaunching proxy with an updated IP and port...', ip, port)
        await stopProxySession();
        startProxySession(undefined, ip, port);
    }
    proxyIP = ip;
    proxyPort = port;
    console.log
}

module.exports = {
    execute,
    pcap, gcap,
    startProxySession, stopProxySession, getSessionStatus, updateProxyIP,
    queuePacket
}

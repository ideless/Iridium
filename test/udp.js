const dgram = require('dgram')
const MHYbuf = require("./util/MHYbuf");
const MT19937_64 = require("./util/mt64");


const hs_buf = Buffer.from('000000ff0000000000000000499602d2ffffffff', 'hex')
const kcp_head_buf = Buffer.from('b0e5090084e76735', 'hex')
const gpt_buf = Buffer.from('51000001c0e486e900000000000000005400000073fb12628f3414bb10380cde005acb0a5bc5dca80a6a3ade772c1ada4cf3f4a7d8d33e98911e549948daceb537f88ee48f3f0d655a772a4d1b9126b3816ba056ed21a5733bb1d905480ac980e4066798f98c1df88de209007fb199d451000001c0e486e901000000000000002000000073fb12e78f3614bb100e0cdd18e332295ed02036e7d49d5878381cbb68874d34', 'hex')
const key_buf = Buffer.from("NpwSwo8/FLsQBRTfKFv7spJeECY6YjvMfh0t6HTFxJ/o4ySwoS5hrCrj/IUCzezcvVs6V2xHGX0rpEWEtQjEb49EnRUP0OsxeGuvstwFP5mZjZRTOouv3emGsQKFhP/TBfWblZBXzuLrgKlWu+0bts5b8YUFAGTZ05wCUcKfvXUuck5h0lGuXxmCxZhQY5fMC1RtwznsQH7xY/shOixJF4yT1NVUyN3yCZ6uNo6eu3/tzsd58rGf0HyMBnW1uUxNTWY5rveRB2Q02sh1hNktpW/aK/GrzPIrZjlMHJaaBJyZoXN4IJx8RM7TW3VQXkGOdc07FqIV2EJ/aS9/zaZmUBkE2OEQCdiMFLqc9IZvu0n30r48CWjtWwPzchZUODlvL5XtlQ00Luvsalho6ipsLIbkKquR/3o2BtdTyqfvpLffQE5/JE44UzRFIdEk7iwyiitryV6JUwmCXy0xU5NUD0BwmKlP6sRcvjAit/FyEjUV2feLtrQd7NxEIPmTcOzIwqH9QXm1Z56HpBUp6hZ8+X5hShbc2NBxKteVssLZnJjE3aEqC0jagw3ATJDPQ8r6/nNEDpg9b/jc/qNIFhfIpbRCOnTuV7eKfFSOBP1Tuj9t8wAbKONQybs+fk/f8uGQjFfuAqw/swN+DsomV2P/59Qewt42b5kF3H2vPEORR1aHvBodmmyfO0cMde+SCiNNcRgN3wPTaAxKPURocskbzQHodI3VepumAehWY8Ggeur3rlsHX4Cp0eU2X2p731u8INXLeGAZWjETQ829iL4lAp/N9HyIfwaxRvpS4vMz5rv1nwsnP8SOqKYB8W9IdPIOK7gnCaekiouBPziI3lHQDALv9pRXzaiy6nURoR0NTKlIjoKMSuHdnjvUGixWQ0NcMph0kFNfsOlY/XOjpjRdPfCQ81ssADVY1drx6LRV4xUVpD8AlicJ7h0HTIzakoH55anEwcN15dGkRZBSgEAbkXuvzkRvc8d/TOfJSoLUC2WLzDX9S3cH4N0wIGMdKP4VvFPOa3/BAeR3ao/8MIMlYd6qNxLW6nGedECVn6vSL5EIqT9vtubzEj6/WTk+ndtHjQv7fO7hmerICsWvtKTqbynU47HLgqrc3dTT42WyM97kAVQk5Wy4GdFzfbdAQo7/gU+UiD5SVuHLjDLcxdZEFb/PGnMCetO7mcS8QdID8Ub6mDPa2II7OkBlXGxKrufcUt6fbS4BdFuvprEPG2cLgeZThovndTXkEMq/5DRTxdua2jletsVfOEQ+Eo5g8hRZQkDQl6jaNEs6eVcIjnADRwYI7ozaB5D0y/n5bH6sGygRt0ekanqUlby3DsHnqrs0VkHOAPRh1gYOKWTcHkOH0sn4vWmhrbCIq+zfajZwHSMbBf9QyP0MNCLFabirbPEFa7cON0pcql3DHh19/OKp+ZDWMKXbw7rwig0AhN6dCzYizSCQUaNN4axJrEePFYTkyar/wKybKozLARW9LmXYFo7Wrq3ROZkNdGVH1Udn+D/4A8g2G9trWyo98j9Mwguz2hNFUGvdCa5aCduutpGSY1bVHD9knLNeqleVqJUOGV0ZaZjzOsgBdR6Df+tuVbr+4wQJ0RXi+M1LUNAnmtTM53BH8O7BEyhoawzb2LyuAD6Mpkj/rhHspHyOXCAYn+ov0D1lem84WjRotE4iiY23OVFoaSiyrUSfejlMVAcUNGj8e8pMXENgMfz9cF2RHZCGq23Cv1V+3+FELc72GbmC5yuh4Z0EjeDaTO4E0oJrowiaU3KqCnc4GzS8eQWuy1JmB5a20gMEu6ronI/LtVVg6LmdgUPl05z6GUREDUtikjCV3P3PabSJ8yMImEtB6TkYATnl5HzxDN9k8KdxAoikZ1viPQ3b1LdgPmObIdjzG3PcxFrr3NHpJ65+heSa81oKW/SP9t4gpDNYWU2woOcs5xfJuwV81PBAwqG3lQKbaE8I7z0zFtimNfs0phk04fNWInzdVfYzhV7K+R5RbaAj4Pwa2OpvETtNcMvJ1ddMDeclivRw1KSfxhx/9o9Z/ytSxUTgPz7MWOXWpqSoUip2UrLsye9BpdmCAz+yt8hZNJuKMA2VlW4guqXCTfVgJ6ujLRScRqTu7+n2IsEHa1hgA2WWrT/LINEqrBFkC4FqlRsEQ4wqtxtup5+reJDu9U/UHIihdQenjWVcvrVtP6yS9Er8OEBfDvnN8ksEbxZZYJIQe6Qs6TG+ZG50gPJSFXYN+vgVZZUSWM7CAyagVgGfGoTGJ4dsDfhnJJ2DKNKDcFt7pAk9bWOcokMX8q/QGSE1an0+FftHW/7u5KqTrUK5iHnljWSa/c6LfgAYhdBvpwSLp3UYUlWBH9UuRgZO0axayGOgHg3B31EgZ6BOc0/4KPDTqX43Auova4g6IY1LdwXD2vTMYNKo2v7P2Yeo9SfQPlTRrFRDh1N+J6b/yZFU405qg6yYk9NaWZrBGcVXmGJlVF7P+7SFMfqFFp9+O5Q2njpMKQv6gR0YQu/SV8yj5awWaWUiWOU9niegckAR6T8dC4MctMRsSO4PQCshsnlanPHXwFI3RYDtk79TlgeN5PowpqT7xe2K7Pcy1lrLNCYpX5JExkdkzfuBVffNKdPNUENtCWvPqPw+VPAwADnMMn+smQKkEsU+V6ORFthGFX93vWn3ICRZYaCemZZrSsuf+FBSIelyPyFLsEc0aTL8nyYcutWuD3QX1td9zuUVXXq66xoPW0InD6+FTAA2SagXlxVkPcDYVXDP9RzCdwmJ1cyyum+EpMXWln5mceUONQ2IyTde+vS4QgX33jT4phY8ur3xAizvq1Z9Nq+mg36dCN6e4mb3bPx/G1gVw1yXPVbPTGd4PIiFAfu4dcz0WBqxzfQjaf5INXWCdhrEQ4UNMvNlmuauGRSkQ3Nzc1NJxretlkCqCzRg0gtq8lnxj8otLNmEYuzZ1BbCwuhPTAwXOD+MA3ERUz/G3EB57wX1mMxJBSDJVCtxWaVU5a0xQypOLKEL3Io4I7KQcGMmWscrnU3eVtjFoP6+V6PPT3fBKW/2HFxVQb0nqZEimtTwandDWPTRKdaxS1Qlyqmhd+fN8G2zChEX9xMcZe+sLGKyh40gAqaeDFSP0e+Oydk28o3VqPtXhAMARMmJp9/fiZD6hFxvn7w/befq5w//oBbjqXvjeoBttKyPx5GcX34YUfoy9OJ1u4lT/gQkKeq3Y0i4GJFy9iKK+o7uX3+U48Mp97YCdphn2MuXhuSTDIswX4+Pqpw2Vxc7VrYmG8huwHrqus2w0crvg00vcogR+RVxqwQaVYXv1eDMjIwfO/IP88Fqj8kF7HCDeYYDB0CNdjUfs2UlUko6Xod5v3Jj6ALu2aoHmTY7/XtxkLhWXwacNTSb3e+uDf4ing4RpRaZS/z+LIgClS2QHxxycqOL/wv3anqVRQzlNREY4C3DkvmhhjIdb2+FU04j1eU/4cf3AbpXvbW7FHYhVBJwVn9wjFRHAZOGp27rWe3ZGUO7e+0KajtCTg1GdxaTg03TzxfxywWwi4ylSLZr1dGMP0rIZ2Fi5kEMcwHxFJDYGVSEPE4a0ZtiDIN8WvfanxjSU7Qf4tKq+u5xiM/bZosIcbDDHuEnqYV/VwQReLmBsNt+fVw0O5b9JGYInwNcHk7naDGK9XFOlrzB4yYVQ83SH8feg3R986WwdKpUm7h7j4Y16tN2Jq3DWA6U0ZK23UNj0zLFQnzL+AXCnQk6Ly/N38eMlB6qBGSaupQQl9Fe8bAloKztX4U6art3EkJQgGRW5IB8Gg7Pfp5famdBqsAFZZxuXedOurnP3X8Pzw5IWwqJTah8GcPsK/iBzQ5BKTG8vQi66oB+ZU08lHT6OdRHi0WCOEYN2AzykSqAPyF13MoYniFjKqIe52n/wUebs0EOwMQIxZ5+HstIsBtD7YCxyYDpJjx3N8PRxqQVU64QDfQKJ99g6Yf30BNByQ4vHl1s3E2Imi1dRPwg9V6QR4ziVqsnAqc/HohZTE0N7E8OEBSjZtwlgZMO8A+cQY8l1SRkZA3qJwb7OvU7xS2CmYkG1BNW8wQDYwijxS2ONMlDleMoDbN2rpOdaqbo2slotC1ujnmIHSnHqKom1EGW6UYLFxD/QXd6DBRuPC5EJ/AvOmSl/n1UL3z9jW3dNOm9mhVcFCLk59aEeghzf5GDHTMFeniRruaLExgf2gNsimR5uayZ9JUTPyBGIvsiUm9dM63p07ihswkgKsgCGo8dZnHvjhKF0xoO2Dg+kIaT0liyWalf5I8BxLbiZ1Oiyj7xUPnrBEsu//jVh+tkAlaY+smcvx/jHc+fdgcsLbh2GNGpn9fAqf4JtvWhRyrmYit5ShDsSQDxdZHRo/ZIs9ZdHytbFmbzBtVx5xP8/AsNVFtpPmgK4PDhCnuTKvxBBRjNGgaOS3YPO4IXcOr8YUwgwWhzrOLvSqF1JYGwRbgGj0atGhCQ3LsBrj5xdByNi1+tYa930dyN+uPbb+VxZfNVuVThoq9D3WMwLEm4ofyLgRCLo56NPdlVcjMwSu0NiTi/z+IPbKrrb8mzEt4lWXSNI7G+i8iaf1+3iumKR+SHnH0W/Cd3plN8k1rNzgmhE85XpY1yJgsKcAppT21s+rLsSVyNt57dokcOUY4YBRnRbjTlt4IGFe2a2La95v8IN5t6cnMz23Xl8nNFNkUCYvq/UISvdDs3oq8pD6Z04K99oXPwDaaTsSJePnlnShajyNZTfGw0XChzNUvNI6qONu0hCpdVgxxR/4PT3KFpNmKbQ51g/h/WYZJVrTHhKOWZKxZ9id3kY9GYjD/SNcwRhA6DFOdSzSix77mjPpJmL7SlLHGJyBukQ7M7W6D1WyqNQoULXiE2SOIpp6NrxtWc1xYKN/vZnBETDJuZAI1L9yuWlzzrusQhXRfEmugGwitZH8jfrI3p38qoYuKEkC0OZTX88biJL0c749N5bFIgYxD9OrYWXrHcxIzfL2cCN+AMnq7gu7ujHpT+XifmFx4hBvGMhY78HBDxmyPTtkcBqbSy3X/2WzJKb2Ui24aoJfucIAZJWEGfndqSZawUrL5aOerwJWr3e9WydlpRbTk+5kqNdMzogv3KvDLU2am7rF+dFEbhzJUCPuY9ZqhlW6UYbEGE3RTRop50rrR2xTEibtzTt9YVAf6Zykw4lI6n1hHCgEIPINeM1yQNYkAzZ6ab7N9fBno0dUJ8Zz+VfH5esEDr5p1FP/Uk3NHMOTORZqVX3/dNx454BwTxukeGEbD9L/rofTRi58WxtI6MRFitc2XaaGj4G06gmLlX4YF6CHTCFPu1aqvHyBZItb8x883OlThh9Zny2SNLFQLYeLzFSLcIwg7oanpfbn2MBeDh5/Bnx5LqjNJsXGWfdEFI2KmLheM9BRfyA2mNXChVYRK8bmgRzt2xJAszf0ZIC0ktooiZ23W8IeoYaU2B2SbBuQ==", 'base64')
const gsfai_head_buf = Buffer.from('5100000169A188E971010000390200001c000000', 'hex')
const gsfai_body_buf = Buffer.from('45670FDD000B000000051801280130d999fafb8E3008F5A2984289AB', 'hex')
const port = 22101
const ip = '47.103.31.140'
const client = dgram.createSocket('udp4')

function send(data, cb) {
    client.send(data, port, ip, (err) => {
        if (err) throw new Error(err)
        cb()
    })
}

function hs() {
    send(hs_buf, () => state = gpt)
}
function gpt(msg) {
    kcp_head_buf.writeUint32BE(msg.readUInt32LE(4), 0)
    kcp_head_buf.writeUint32BE(msg.readUInt32LE(8), 4)
    MHYbuf.xorData(gsfai_body_buf, key_buf)
    send([kcp_head_buf, gsfai_head_buf, gsfai_body_buf], () => state = end)
    // send([kcp_head_buf, gpt_buf], () => state = gsfai)
}
async function gsfai(msg) {
    if (msg.byteLength < 200) return
    msg = msg.slice(28)
    MHYbuf.xorData(msg, key_buf)
    let proto = await MHYbuf.dataToProtobuffer(MHYbuf.parsePacketData(msg), "GetPlayerTokenRsp")
    console.log('key seed', proto.secretKeySeed.toString())
    let initgen = new MT19937_64();
    initgen.seed(BigInt(proto.secretKeySeed));
    let generator = new MT19937_64();
    generator.seed(initgen.int64());
    generator.int64();
    for (let i = 0; i < 4096; i += 8) {
        let val = generator.int64();
        key_buf.writeBigUInt64BE(val, i)
    }
    MHYbuf.xorData(gsfai_body_buf, key_buf)
    send([kcp_head_buf, gsfai_head_buf, gsfai_body_buf], () => state = end)
}
function end(msg) {
}
let state = hs

client.on('error', (err) => {
    console.log(`client error:\n${err.stack}`);
    client.close();
});

client.on('message', (msg, rinfo) => {
    // console.log(`message from ${rinfo.address}:${rinfo.port}:`)
    // console.log(msg)
    state(msg)
});

client.on('listening', () => {
    const address = client.address();
    console.log(`client listening ${address.address}:${address.port}`);
});

client.bind()

state()
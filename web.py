"""
Yar İletişim (web) - telefon + bilgisayar, uçtan uca şifreli sohbet ve sesli arama.

Çalıştır:  pip install aiohttp cryptography
           python yar_web.py            (varsayılan port 8443)

Aynı ağdaki her cihazın tarayıcısında ekranda yazan https://IP:8443 adresini aç.
Sertifika uyarısı çıkar (kendi imzaladığımız sertifika), "Gelişmiş > devam et" de.
"""
import sys, os, json, asyncio, socket, ssl, ipaddress, datetime, webbrowser
from aiohttp import web, WSMsgType
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

HERE = os.path.dirname(os.path.abspath(__file__))
CERT, KEY, IPS = (os.path.join(HERE, n) for n in ("yar_cert.pem", "yar_key.pem", "yar_cert.ips"))
MAX_ROOM = 50
rooms = {}


# ===================== SERTİFİKA (telefonda mikrofon için HTTPS şart) =====================
def local_ips():
    ips = set()
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ips.add(s.getsockname()[0])
        s.close()
    except Exception:
        pass
    try:
        for ip in socket.gethostbyname_ex(socket.gethostname())[2]:
            if not ip.startswith("127."):
                ips.add(ip)
    except Exception:
        pass
    return sorted(ips)


def ensure_cert(ips):
    if os.path.exists(CERT) and os.path.exists(KEY) and os.path.exists(IPS):
        try:
            if set(ips) <= set(json.load(open(IPS))):
                return
        except Exception:
            pass
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Yar Iletisim")])
    san = [x509.DNSName("localhost"), x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]
    san += [x509.IPAddress(ipaddress.ip_address(i)) for i in ips]
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=365))
            .add_extension(x509.SubjectAlternativeName(san), False)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), True)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), False)
            .sign(key, hashes.SHA256()))
    open(CERT, "wb").write(cert.public_bytes(serialization.Encoding.PEM))
    open(KEY, "wb").write(key.private_bytes(serialization.Encoding.PEM,
                                            serialization.PrivateFormat.PKCS8,
                                            serialization.NoEncryption()))
    json.dump(ips, open(IPS, "w"))


# ===================== SUNUCU (sadece şifreli veriyi iletir) =====================
async def ws_handler(request):
    ws = web.WebSocketResponse(max_msg_size=262144, heartbeat=30)
    await ws.prepare(request)
    rid = None
    try:
        async for msg in ws:
            if msg.type != WSMsgType.TEXT:
                continue
            if rid is None:
                d = json.loads(msg.data)
                r = d.get("room", "")
                if not (isinstance(r, str) and len(r) == 64 and all(c in "0123456789abcdef" for c in r)):
                    break
                room = rooms.setdefault(r, set())
                if len(room) >= MAX_ROOM:
                    break
                room.add(ws)
                rid = r
                continue
            for o in list(rooms.get(rid, ())):
                if o is not ws and not o.closed:
                    await o.send_str(msg.data)
    except Exception:
        pass
    finally:
        if rid in rooms:
            rooms[rid].discard(ws)
            if not rooms[rid]:
                del rooms[rid]
    return ws


HEADERS = {
    "Cache-Control": "no-store",
    "Content-Security-Policy": "default-src 'self'; script-src 'unsafe-inline'; "
                               "style-src 'unsafe-inline'; connect-src 'self' wss: ws:; "
                               "media-src blob: 'self'; img-src data:",
    "X-Content-Type-Options": "nosniff",
}


async def index(request):
    return web.Response(text=PAGE, content_type="text/html", headers=HEADERS)


async def manifest(request):
    return web.json_response({"name": "Yar İletişim", "short_name": "Yar", "start_url": "/",
                              "display": "standalone", "background_color": "#0f1115",
                              "theme_color": "#0f1115"})


async def main(port):
    ips = local_ips()
    ensure_cert(ips)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(CERT, KEY)
    app = web.Application()
    app.router.add_get("/", index)
    app.router.add_get("/manifest.json", manifest)
    app.router.add_get("/ws", ws_handler)
    runner = web.AppRunner(app)
    await runner.setup()
    await web.TCPSite(runner, "0.0.0.0", port, ssl_context=ctx).start()
    print("Yar İletişim çalışıyor. Cihazlarda şu adresi aç:")
    print(f"  bu bilgisayar : https://localhost:{port}")
    for ip in ips:
        print(f"  aynı ağ       : https://{ip}:{port}")
    print("Sertifika uyarısı çıkarsa 'Gelişmiş > devam et' de. Durdurmak için Ctrl+C.")
    try:
        webbrowser.open(f"https://localhost:{port}")
    except Exception:
        pass
    await asyncio.Event().wait()


# ===================== İSTEMCİ (tarayıcıda çalışır; şifreleme burada) =====================
PAGE = r"""<!DOCTYPE html><html lang="tr"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<meta name="theme-color" content="#0f1115"><meta name="mobile-web-app-capable" content="yes">
<meta name="apple-mobile-web-app-capable" content="yes">
<link rel="manifest" href="/manifest.json"><title>Yar İletişim</title>
<style>
*{box-sizing:border-box}[hidden]{display:none!important}
html,body{height:100%;margin:0}
body{background:#0f1115;color:#e3e3e3;font-family:system-ui,"Segoe UI",Arial,sans-serif}
.box{max-width:380px;margin:0 auto;padding:10vh 24px 24px}
h1{font-size:28px;margin:0 0 4px;letter-spacing:2px}
.sub{color:#6b7280;font-size:13px;margin-bottom:12px}
label{display:block;color:#6b7280;font-size:12px;margin:14px 0 4px}
input{width:100%;padding:12px 14px;font-size:16px;color:#eee;background:#171a21;border:1px solid #2c303a;border-radius:8px;outline:none}
input:focus{border-color:#6b7280}
button{font-size:15px;color:#eee;background:#2a2e38;border:0;border-radius:8px;padding:12px 16px;cursor:pointer}
button:active{background:#3a3f4b}
#go{width:100%;margin-top:20px}
.err{color:#ff7a7a;font-size:13px;min-height:18px;margin-top:10px}
#chat{display:flex;flex-direction:column;height:100dvh}
.top{display:flex;align-items:center;gap:8px;padding:10px 14px;background:#15171c;border-bottom:1px solid #22252d}
.top b{flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.top button{padding:8px 12px}
#st{color:#81c995;font-size:12px}
#msgs{flex:1;overflow-y:auto;padding:12px 14px}
.m{margin-bottom:8px;line-height:1.4;word-wrap:break-word}
.m small{color:#6b7280;margin-right:6px}
.m .w{color:#8ab4f8;font-weight:600}.m.me .w{color:#81c995}
.sys{color:#6b7280;font-style:italic;font-size:13px;margin-bottom:8px}
.bar{display:flex;gap:8px;padding:10px;background:#15171c;padding-bottom:calc(10px + env(safe-area-inset-bottom))}
.bar input{flex:1}
#incoming{position:fixed;inset:0;background:#000b;display:flex;align-items:center;justify-content:center;z-index:9}
#incoming div{background:#171a21;padding:26px;border-radius:12px;text-align:center;min-width:250px}
#incoming p{font-size:18px;margin:0 0 18px}
.gr{background:#1f6f43}.rd{background:#8a2b2b}
</style></head><body>
<div id="login" class="box">
 <h1>YAR</h1><div class="sub">uçtan uca şifreli sohbet ve arama</div>
 <label>Takma ad</label><input id="name" autocomplete="off">
 <label>Oda adı</label><input id="room" autocomplete="off" autocapitalize="off">
 <label>Oda parolası (anahtar buradan çıkar, uzun yaz)</label><input id="pw" type="password" autocomplete="off">
 <button id="go">Bağlan</button><div class="err" id="err"></div>
</div>
<div id="chat" hidden>
 <div class="top"><b id="rn"></b><span id="st"></span>
  <button id="call" title="Ara">📞</button><button id="mute" title="Sessize al" hidden>🎙️</button>
  <button id="hang" class="rd" title="Kapat" hidden>⏹</button></div>
 <div id="msgs"></div>
 <div class="bar"><input id="inp" autocomplete="off" placeholder="Mesaj yaz..."><button id="snd">Gönder</button></div>
</div>
<div id="incoming" hidden><div><p id="who"></p>
 <button id="acc" class="gr">Kabul</button> <button id="rej" class="rd">Reddet</button></div></div>
<audio id="remote" autoplay playsinline></audio>
<script>
(function(){
var $=function(i){return document.getElementById(i)};
var enc=new TextEncoder(),dec=new TextDecoder();
var ICE=[{urls:"stun:stun.l.google.com:19302"}];
var ws=null,K=null,me={name:"",sid:""};
var pc=null,localStream=null,callPeer=null,pendingOffer=null,iceBuf=[],callTimer=null;

function b64e(u){var s="";for(var i=0;i<u.length;i++)s+=String.fromCharCode(u[i]);return btoa(s)}
function b64d(s){var b=atob(s),u=new Uint8Array(b.length);for(var i=0;i<b.length;i++)u[i]=b.charCodeAt(i);return u}
function hex(u){return Array.from(u,function(x){return x.toString(16).padStart(2,"0")}).join("")}
me.sid=hex(crypto.getRandomValues(new Uint8Array(8)));

async function derive(room,pw){
 var base=await crypto.subtle.importKey("raw",enc.encode(pw),"PBKDF2",false,["deriveBits"]);
 async function kd(tag){return new Uint8Array(await crypto.subtle.deriveBits(
  {name:"PBKDF2",salt:enc.encode("yar-"+tag+"|"+room),iterations:250000,hash:"SHA-256"},base,256))}
 var id=hex(await kd("id"));
 var key=await crypto.subtle.importKey("raw",await kd("key"),"AES-GCM",false,["encrypt","decrypt"]);
 return {id:id,key:key};
}
async function seal(o){
 var iv=crypto.getRandomValues(new Uint8Array(12));
 var ct=new Uint8Array(await crypto.subtle.encrypt({name:"AES-GCM",iv:iv},K,enc.encode(JSON.stringify(o))));
 var out=new Uint8Array(12+ct.length);out.set(iv);out.set(ct,12);return b64e(out);
}
async function unseal(s){
 try{var u=b64d(s);
  var pt=await crypto.subtle.decrypt({name:"AES-GCM",iv:u.slice(0,12)},K,u.slice(12));
  return JSON.parse(dec.decode(pt));}catch(e){return null}
}
async function send(o){
 o.n=me.name;o.f=me.sid;o.ts=Date.now();
 if(ws&&ws.readyState===1)ws.send(JSON.stringify({c:await seal(o)}));
}

function line(cls,parts){
 var d=document.createElement("div");d.className=cls;
 parts.forEach(function(p){var e=document.createElement(p.t||"span");if(p.c)e.className=p.c;e.textContent=p.x;d.appendChild(e)});
 var box=$("msgs");box.appendChild(d);box.scrollTop=box.scrollHeight;
}
function sys(t){line("sys",[{x:t}])}
function msg(who,text,ts,mine){
 var t=new Date(ts||Date.now()),hh=("0"+t.getHours()).slice(-2)+":"+("0"+t.getMinutes()).slice(-2);
 line("m"+(mine?" me":""),[{t:"small",x:hh},{c:"w",x:who+": "},{x:text}]);
}

// ---------- bağlanma ----------
$("go").onclick=async function(){
 var name=$("name").value.trim(),room=$("room").value.trim(),pw=$("pw").value;
 if(!name||!room||pw.length<6){$("err").textContent="Ad, oda ve en az 6 karakterlik parola gerekli.";return}
 $("go").disabled=true;$("err").textContent="Anahtar türetiliyor...";
 var d;
 try{d=await derive(room,pw)}catch(e){$("err").textContent="Bu tarayıcı şifrelemeyi desteklemiyor (HTTPS gerekli).";$("go").disabled=false;return}
 K=d.key;me.name=name;
 ws=new WebSocket((location.protocol==="https:"?"wss://":"ws://")+location.host+"/ws");
 ws.onopen=function(){ws.send(JSON.stringify({room:d.id}));
  $("login").hidden=true;$("chat").hidden=false;$("rn").textContent="# "+room;$("st").textContent="🔒";
  sys("Bağlandın. Aynı oda adı ve parolayı girenler seni görür. Aramalar birebir çalışır.");
  send({k:"join"});$("inp").focus()};
 ws.onmessage=async function(e){var m;try{m=JSON.parse(e.data)}catch(x){return}
  var o=await unseal(m.c);if(o)handle(o)};
 ws.onclose=function(){if($("chat").hidden){$("err").textContent="Sunucuya bağlanılamadı.";$("go").disabled=false}
  else{sys("Sunucuyla bağlantı koptu.");cleanup()}};
};
$("pw").onkeydown=function(e){if(e.key==="Enter")$("go").click()};

function sendText(){
 var t=$("inp").value.trim();if(!t)return;$("inp").value="";
 send({k:"m",t:t.slice(0,2000)});msg("sen",t,Date.now(),true);
}
$("snd").onclick=sendText;
$("inp").onkeydown=function(e){if(e.key==="Enter")sendText()};

// ---------- gelen şifreli olaylar ----------
function fresh(o){return Math.abs(Date.now()-(o.ts||0))<120000}
function handle(o){
 if(o.f===me.sid)return;
 if(o.to&&o.to!==me.sid)return;
 var k=o.k;
 if(k==="m")msg(String(o.n||"?"),String(o.t||""),o.ts,false);
 else if(k==="join")sys(String(o.n||"?")+" katıldı");
 else if(k==="leave")sys(String(o.n||"?")+" ayrıldı");
 else if(!fresh(o))return;
 else if(k==="offer"){
  if(pc||pendingOffer){send({k:"busy",to:o.f});return}
  pendingOffer=o;$("who").textContent="📞 "+String(o.n||"?")+" arıyor";$("incoming").hidden=false;
 }
 else if(k==="answer"){
  if(pc&&!callPeer){callPeer=o.f;pc.setRemoteDescription(o.sdp).then(flush).catch(function(){sys("Arama kurulamadı.");cleanup()})}
 }
 else if(k==="ice"){
  var mine=(o.f===callPeer)||(pendingOffer&&pendingOffer.f===o.f)||(pc&&!callPeer);
  if(!mine||!o.c)return;
  if(pc&&pc.remoteDescription)pc.addIceCandidate(o.c).catch(function(){});else iceBuf.push(o.c);
 }
 else if(k==="busy"){if(pc&&!callPeer){sys("Karşı taraf meşgul.");cleanup()}}
 else if(k==="bye"){
  if(o.f===callPeer||(pendingOffer&&pendingOffer.f===o.f)){sys("Arama sona erdi.");cleanup()}
 }
}
function flush(){var b=iceBuf;iceBuf=[];b.forEach(function(c){pc.addIceCandidate(c).catch(function(){})})}

// ---------- sesli arama (WebRTC: ses doğrudan cihazdan cihaza, DTLS-SRTP şifreli) ----------
function ui(state){
 $("call").hidden=state!=="idle";$("hang").hidden=state==="idle";$("mute").hidden=state!=="active";
 $("st").textContent=state==="idle"?"🔒":state==="calling"?"🔒 aranıyor...":"🔒 görüşmede";
}
function cleanup(){
 clearTimeout(callTimer);
 if(pc){try{pc.close()}catch(e){}pc=null}
 if(localStream){localStream.getTracks().forEach(function(t){t.stop()});localStream=null}
 callPeer=null;pendingOffer=null;iceBuf=[];$("remote").srcObject=null;
 $("incoming").hidden=true;$("mute").textContent="🎙️";ui("idle");
}
async function makePC(){
 pc=new RTCPeerConnection({iceServers:ICE});
 pc.onicecandidate=function(e){if(e.candidate)send({k:"ice",to:callPeer,c:e.candidate.toJSON()})};
 pc.ontrack=function(e){$("remote").srcObject=e.streams[0];$("remote").play().catch(function(){})};
 pc.onconnectionstatechange=function(){
  if(!pc)return;
  if(pc.connectionState==="connected"){clearTimeout(callTimer);ui("active")}
  else if(["failed","closed"].indexOf(pc.connectionState)>=0){sys("Bağlantı kurulamadı ya da koptu.");cleanup()}
 };
 localStream=await navigator.mediaDevices.getUserMedia({audio:true});
 localStream.getTracks().forEach(function(t){pc.addTrack(t,localStream)});
}
$("call").onclick=async function(){
 if(pc)return;ui("calling");sys("Aranıyor...");
 try{
  await makePC();
  var off=await pc.createOffer();await pc.setLocalDescription(off);
  send({k:"offer",sdp:{type:off.type,sdp:off.sdp}});
  callTimer=setTimeout(function(){if(pc&&!callPeer){send({k:"bye"});sys("Cevap yok.");cleanup()}},45000);
 }catch(e){sys("Mikrofon açılamadı (izin ver ve HTTPS adresinde olduğundan emin ol).");cleanup()}
};
$("acc").onclick=async function(){
 var o=pendingOffer;if(!o)return;$("incoming").hidden=true;callPeer=o.f;
 try{
  await makePC();await pc.setRemoteDescription(o.sdp);flush();
  var a=await pc.createAnswer();await pc.setLocalDescription(a);
  send({k:"answer",to:callPeer,sdp:{type:a.type,sdp:a.sdp}});pendingOffer=null;ui("calling");
 }catch(e){sys("Arama kabul edilemedi.");cleanup()}
};
$("rej").onclick=function(){if(pendingOffer)send({k:"bye",to:pendingOffer.f});pendingOffer=null;$("incoming").hidden=true};
$("hang").onclick=function(){send({k:"bye",to:callPeer});sys("Aramayı kapattın.");cleanup()};
$("mute").onclick=function(){
 if(!localStream)return;var on=true;
 localStream.getAudioTracks().forEach(function(t){t.enabled=!t.enabled;on=t.enabled});
 $("mute").textContent=on?"🎙️":"🔇";
};
window.addEventListener("beforeunload",function(){if(ws&&ws.readyState===1){send({k:"leave"});if(callPeer)send({k:"bye",to:callPeer})}});
})();
</script></body></html>"""


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8443
    try:
        asyncio.run(main(port))
    except KeyboardInterrupt:
        pass

import asyncio
import time
import httpx
import json
import os
import io
import base64
from collections import defaultdict
from flask import Flask, request, jsonify, render_template_string, Response
from flask_cors import CORS
from google.protobuf import json_format
from Crypto.Cipher import AES
from PIL import Image, ImageDraw, ImageFont

# ============= PATH FIX =============
import sys
current_dir = os.path.dirname(os.path.abspath(__file__))
proto_dir = os.path.join(current_dir, 'proto')
if proto_dir not in sys.path:
    sys.path.insert(0, proto_dir)

# Import proto files
try:
    from proto import FreeFire_pb2, main_pb2, AccountPersonalShow_pb2
    print("✅ Proto files imported successfully")
except ImportError:
    try:
        import FreeFire_pb2, main_pb2, AccountPersonalShow_pb2
        print("✅ Proto files imported directly")
    except ImportError as e:
        print(f"❌ Proto import error: {e}")
        sys.exit(1)

# ============= সিকিউরিটি কী ও ধ্রুবক =============
MAIN_KEY = base64.b64decode('WWcmdGMlREV1aDYlWmNeOA==')
MAIN_IV = base64.b64decode('Nm95WkRyMjJFM3ljaGpNJQ==')
USERAGENT = "Dalvik/2.1.0 (Linux; U; Android 13; CPH2095 Build/RKQ1.211119.001)"
REGION_PRIORITY = ["ME", "BD", "IND"]
SUPPORTED_REGIONS = set(REGION_PRIORITY)

# ============= Flask App =============
app = Flask(__name__)
CORS(app)

@app.errorhandler(Exception)
def handle_any_error(e):
    # ফ্লাস্কের ডিফল্ট HTML error page বন্ধ, সবসময় JSON রিটার্ন
    code = getattr(e, 'code', 500)
    return jsonify({"error": str(e)}), code if isinstance(code, int) else 500

# ইন-মেমোরি ক্যাশ (Vercel-এ রিকোয়েস্ট জুড়ে থাকতে পারে, cold start এ খালি হয়)
cached_tokens = defaultdict(dict)
key_store = {
    'api_key': base64.b64encode(b'KAWSAR').decode(),
    'admin_key': base64.b64encode(b'449KAWSAR').decode()
}
cached_config = {
    'login_url': None,
    'version': None,
    'last_update': 0
}

def check_api_key(key: str) -> bool:
    stored = base64.b64decode(key_store['api_key']).decode()
    return key == stored

def check_admin_key(key: str) -> bool:
    stored = base64.b64decode(key_store['admin_key']).decode()
    return key == stored

# ============= কনফিগ (ঠান্ডা স্টার্ট এলে আপডেট হয়) =============
async def update_config():
    """প্রতি রিকোয়েস্টের আগে চেক, ৩০ মিনিট পুরনো হলে রিফ্রেশ"""
    if cached_config['last_update'] and (time.time() - cached_config['last_update']) < 1800:
        return  # এখনও ফ্রেশ

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get("https://mg24-auto-update.vercel.app/")
            if resp.status_code == 200:
                data = resp.json()
                src = data.get("SourceUpdate_info", {})
                cached_config['version'] = src.get("latest_release_version")
                raw_login = src.get("server_url", "").rstrip("/")
                if raw_login and not raw_login.endswith("/MajorLogin"):
                    raw_login += "/MajorLogin"
                cached_config['login_url'] = raw_login
                cached_config['last_update'] = time.time()
                print(f"✅ Config updated: version={cached_config['version']}")
    except Exception as e:
        print(f"❌ Config update error: {e}")

def config_ready() -> bool:
    return cached_config['login_url'] is not None and cached_config['version'] is not None

# ============= টোকেন =============
async def create_jwt(region: str):
    account = get_account_credentials(region)
    token_val, open_id = await get_access_token(account)
    if not token_val or not open_id:
        print(f"❌ Failed to get access token for {region}")
        return False

    body = json.dumps({
        "open_id": open_id, "open_id_type": "4",
        "login_token": token_val, "orign_platform_type": "4"
    })
    proto_bytes = await json_to_proto(body, FreeFire_pb2.LoginReq())
    payload = aes_cbc_encrypt(MAIN_KEY, MAIN_IV, proto_bytes)

    url = cached_config['login_url']
    headers = {
        'User-Agent': USERAGENT, 'Connection': "Keep-Alive", 'Accept-Encoding': "gzip",
        'Content-Type': "application/octet-stream", 'Expect': "100-continue",
        'X-Unity-Version': "2018.4.11f1", 'X-GA': "v1 1",
        'ReleaseVersion': cached_config['version']
    }

    async with httpx.AsyncClient(timeout=30.0) as client:
        resp = await client.post(url, data=payload, headers=headers)
        if resp.status_code != 200:
            print(f"❌ MajorLogin returned {resp.status_code} for {region}")
            return False

        login_res = FreeFire_pb2.LoginRes()
        login_res.ParseFromString(resp.content)
        msg = json.loads(json_format.MessageToJson(login_res))

        cached_tokens[region] = {
            'token': f"Bearer {msg.get('token','0')}",
            'region': msg.get('lockRegion','0'),
            'server_url': msg.get('serverUrl','0'),
            'expires_at': time.time() + 25200
        }
        print(f"✅ Token generated for {region}")
        return True

async def get_token_info(region: str):
    """টোকেন থাকলে দেয়, না থাকলে জেনারেট করে"""
    info = cached_tokens.get(region)
    if info and info['expires_at'] > time.time():
        return info['token'], info['region'], info['server_url']

    success = await create_jwt(region)
    if not success:
        return None, None, None

    info = cached_tokens[region]
    return info['token'], info['region'], info['server_url']

# ============= সহায়ক ফাংশন =============
def pad(text: bytes) -> bytes:
    padding_length = AES.block_size - (len(text) % AES.block_size)
    return text + bytes([padding_length] * padding_length)

def aes_cbc_encrypt(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    aes = AES.new(key, AES.MODE_CBC, iv)
    return aes.encrypt(pad(plaintext))

async def json_to_proto(json_data: str, proto_message) -> bytes:
    json_format.ParseDict(json.loads(json_data), proto_message)
    return proto_message.SerializeToString()

def get_account_credentials(region: str) -> str:
    r = region.upper()
    if r == "ME":
        return "uid=3301535568&password=BEC9F99733AC7B1FB139DB3803F90A7E78757B0BE395E0A6FE3A520AF77E0517"
    elif r == "BD":
        return "uid=3301828218&password=3A0E972E57E9EDC39DC4830E3D486DBFB5DA7C52A4E8B0B8F3F9DC4450899571"
    elif r == "IND":
        return "uid=4289924053&password=68C6CF86ED35E535144488384ED282C6C0E9597E9FE6A162DE03F6AF6D1B2B7C"
    else:
        return "uid=4269012488&password=MG24_GAMER_U27YB_BY_SPIDEERIO_GAMING_0PNCN"

async def get_access_token(account: str):
    url = "https://ffmconnect.live.gop.garenanow.com/oauth/guest/token/grant"
    payload = account + "&response_type=token&client_type=2&client_secret=2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3&client_id=100067"
    headers = {'User-Agent': USERAGENT, 'Content-Type': "application/x-www-form-urlencoded"}
    for _ in range(3):
        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                resp = await client.post(url, data=payload, headers=headers)
                if resp.status_code == 200:
                    data = resp.json()
                    return data.get("access_token"), data.get("open_id")
        except:
            await asyncio.sleep(2)
    return None, None

async def GetAccountInformation(uid, region):
    try:
        token, _, server_url = await get_token_info(region)
        if not token:
            return None

        payload = await json_to_proto(json.dumps({'a': uid, 'b': '7'}), main_pb2.GetPlayerPersonalShow())
        data_enc = aes_cbc_encrypt(MAIN_KEY, MAIN_IV, payload)

        headers = {
            'User-Agent': USERAGENT, 'Connection': "Keep-Alive", 'Accept-Encoding': "gzip",
            'Content-Type': "application/octet-stream", 'Expect': "100-continue",
            'Authorization': token, 'X-Unity-Version': "2018.4.11f1", 'X-GA': "v1 1",
            'ReleaseVersion': cached_config['version']
        }

        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.post(server_url + '/GetPlayerPersonalShow', data=data_enc, headers=headers)
            if resp.status_code != 200:
                print(f"❌ API returned {resp.status_code} for {region}")
                return None

            account_info = AccountPersonalShow_pb2.AccountPersonalShowInfo()
            account_info.ParseFromString(resp.content)
            result = json.loads(json_format.MessageToJson(account_info))
            print(f"✅ Info received for UID {uid} from {region}")
            return result

    except Exception as e:
        print(f"❌ GetAccountInformation error: {e}")
        return None

def format_response(data):
    if not data:
        return {"error": "No data"}
    basic = data.get("basicInfo", {})
    clan = data.get("clanBasicInfo", {})
    return {
        "AccountInfo": {
            "AccountAvatarId": basic.get("headPic"),
            "AccountBPBadges": basic.get("badgeCnt"),
            "AccountBPID": basic.get("badgeId"),
            "AccountBannerId": basic.get("bannerId"),
            "AccountCreateTime": basic.get("createAt"),
            "AccountEXP": basic.get("exp"),
            "AccountLastLogin": basic.get("lastLoginAt"),
            "AccountLevel": basic.get("level"),
            "AccountLikes": basic.get("liked"),
            "AccountName": basic.get("nickname"),
            "AccountRegion": basic.get("region"),
            "AccountSeasonId": basic.get("seasonId"),
            "AccountType": basic.get("accountType"),
            "BrMaxRank": basic.get("maxRank"),
            "BrRankPoint": basic.get("rankingPoints"),
            "CsMaxRank": basic.get("csMaxRank"),
            "CsRankPoint": basic.get("csRankingPoints"),
            "EquippedWeapon": basic.get("weaponSkinShows", []),
            "ReleaseVersion": basic.get("releaseVersion"),
            "ShowBrRank": basic.get("showBrRank"),
            "ShowCsRank": basic.get("showCsRank"),
            "Title": basic.get("title")
        },
        "AccountProfileInfo": {
            "EquippedOutfit": data.get("profileInfo", {}).get("clothes", []),
            "EquippedSkills": data.get("profileInfo", {}).get("equipedSkills", [])
        },
        "GuildInfo": {
            "GuildCapacity": clan.get("capacity"),
            "GuildID": str(clan.get("clanId")),
            "GuildLevel": clan.get("clanLevel"),
            "GuildMember": clan.get("memberNum"),
            "GuildName": clan.get("clanName"),
            "GuildOwner": str(clan.get("captainId"))
        },
        "captainBasicInfo": data.get("captainBasicInfo", {}),
        "creditScoreInfo": data.get("creditScoreInfo", {}),
        "petInfo": data.get("petInfo", {}),
        "socialinfo": data.get("socialInfo", {})
    }

# ============= ব্যানার ইমেজ জেনারেশন =============
ICON_CDN_BASE64 = "aHR0cHM6Ly9jZG4uanNkZWxpdnIubmV0L2doL1NoYWhHQ3JlYXRvci9pY29uQG1haW4vUE5H"
ICON_CDN_URL = base64.b64decode(ICON_CDN_BASE64).decode("utf-8")

FONT_FILE = os.path.join(current_dir, "Road_Rage.otf")
FONT_CHEROKEE = os.path.join(current_dir, "Road_Rage.otf")

AVATAR_ZOOM = 1.26
AVATAR_SHIFT_Y = 0
AVATAR_SHIFT_X = 0
BANNER_START_X = 0.25
BANNER_START_Y = 0.29
BANNER_END_X = 0.81
BANNER_END_Y = 0.65

def load_unicode_font(size, font_path=FONT_FILE):
    try:
        if os.path.exists(font_path):
            return ImageFont.truetype(font_path, size)
    except Exception:
        pass
    return ImageFont.load_default()

async def fetch_icon_bytes(item_id):
    if not item_id or str(item_id) in ("0", "None"):
        return None
    try:
        async with httpx.AsyncClient(timeout=10.0, follow_redirects=True) as client:
            resp = await client.get(f"{ICON_CDN_URL}/{item_id}.png")
            if resp.status_code == 200:
                return resp.content
    except Exception:
        pass
    return None

def bytes_to_image(img_bytes):
    if img_bytes:
        try:
            return Image.open(io.BytesIO(img_bytes)).convert("RGBA")
        except Exception:
            pass
    return Image.new("RGBA", (100, 100), (0, 0, 0, 0))

def is_cherokee(ch):
    return 0x13A0 <= ord(ch) <= 0x13FF or 0xAB70 <= ord(ch) <= 0xABBF

def build_banner_image(name, level, guild, avatar_bytes, banner_bytes, pin_bytes):
    avatar_img = bytes_to_image(avatar_bytes)
    banner_img = bytes_to_image(banner_bytes)
    pin_img = bytes_to_image(pin_bytes)

    TARGET_HEIGHT = 400

    zoom_size = int(TARGET_HEIGHT * AVATAR_ZOOM)
    avatar_img = avatar_img.resize((zoom_size, zoom_size), Image.LANCZOS)
    c = zoom_size // 2
    h = TARGET_HEIGHT // 2
    avatar_img = avatar_img.crop((
        c - h - AVATAR_SHIFT_X, c - h - AVATAR_SHIFT_Y,
        c + h - AVATAR_SHIFT_X, c + h - AVATAR_SHIFT_Y
    ))

    banner_img = banner_img.rotate(3, expand=True)
    bw, bh = banner_img.size
    banner_img = banner_img.crop((bw * BANNER_START_X, bh * BANNER_START_Y, bw * BANNER_END_X, bh * BANNER_END_Y))
    bw, bh = banner_img.size
    banner_img = banner_img.resize((int(TARGET_HEIGHT * (bw / bh) * 2), TARGET_HEIGHT), Image.LANCZOS)

    final = Image.new("RGBA", (avatar_img.width + banner_img.width, TARGET_HEIGHT))
    final.paste(avatar_img, (0, 0))
    final.paste(banner_img, (avatar_img.width, 0))

    draw = ImageDraw.Draw(final)
    font_big = load_unicode_font(125)
    font_big_c = load_unicode_font(125, FONT_CHEROKEE)
    font_small = load_unicode_font(95)
    font_small_c = load_unicode_font(95, FONT_CHEROKEE)
    font_lvl = load_unicode_font(50)

    def draw_text(x, y, text, f_main, f_alt, stroke):
        text = text or ""
        cx = x
        for ch in text:
            f = f_alt if is_cherokee(ch) else f_main
            for dx in range(-stroke, stroke + 1):
                for dy in range(-stroke, stroke + 1):
                    draw.text((cx + dx, y + dy), ch, font=f, fill="black")
            draw.text((cx, y), ch, font=f, fill="white")
            cx += f.getlength(ch)

    draw_text(avatar_img.width + 65, 40, name or "Unknown", font_big, font_big_c, 4)
    draw_text(avatar_img.width + 65, 220, guild or "", font_small, font_small_c, 3)

    if pin_img.size != (100, 100):
        pin_img = pin_img.resize((130, 130))
        final.paste(pin_img, (0, TARGET_HEIGHT - 130), pin_img)

    lvl = f"Lvl.{level or 0}"
    w, h_txt = draw.textbbox((0, 0), lvl, font=font_lvl)[2:]
    draw.rectangle([final.width - w - 60, TARGET_HEIGHT - h_txt - 50, final.width, TARGET_HEIGHT], fill="black")
    draw.text((final.width - w - 30, TARGET_HEIGHT - h_txt - 40), lvl, font=font_lvl, fill="white")

    out = io.BytesIO()
    final.save(out, "PNG")
    out.seek(0)
    return out

async def generate_banner_png(raw_data):
    """raw_data হলো GetAccountInformation থেকে সরাসরি পাওয়া ডাটা, বাইরের কোনো info API লাগবে না"""
    basic = raw_data.get("basicInfo", {})
    clan = raw_data.get("clanBasicInfo", {})

    name = basic.get("nickname")
    level = basic.get("level")
    guild = clan.get("clanName")
    avatar_id = basic.get("headPic")
    banner_id = basic.get("bannerId")
    pin_id = basic.get("pinId")

    avatar_bytes, banner_bytes, pin_bytes = await asyncio.gather(
        fetch_icon_bytes(avatar_id),
        fetch_icon_bytes(banner_id),
        fetch_icon_bytes(pin_id),
    )

    loop = asyncio.get_event_loop()
    img_io = await loop.run_in_executor(
        None, build_banner_image, name, level, guild, avatar_bytes, banner_bytes, pin_bytes
    )
    return img_io

# ============= আউটফিট শোকেস ইমেজ জেনারেশন =============
OUTFIT_BG_FILE = os.path.join(current_dir, "outfit_bg.mp4")
# (center_x, center_y, ring_radius) - সরাসরি ব্যাকগ্রাউন্ড ছবি থেকে মেপে বের করা
OUTFIT_RING_SLOTS = [
    (182, 169, 86), (433, 305, 75), (989, 302, 90), (1220, 169, 75),
    (173, 626, 81), (1223, 628, 92), (449, 865, 89), (250, 980, 88),
    (1013, 850, 87),
]
RING_PADDING = 16  # গ্লো বর্ডারের সাথে ওভারল্যাপ এড়াতে

def make_circular_icon(img_bytes, size):
    icon = bytes_to_image(img_bytes).resize((size, size), Image.LANCZOS)
    mask = Image.new("L", (size, size), 0)
    ImageDraw.Draw(mask).ellipse((0, 0, size, size), fill=255)
    out = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    out.paste(icon, (0, 0), mask)
    return out

async def generate_outfit_png(raw_data):
    profile = raw_data.get("profileInfo", {})
    basic = raw_data.get("basicInfo", {})
    clothes = list(profile.get("clothes", []) or [])

    pet_skin = (raw_data.get("petInfo", {}) or {}).get("skinId")
    if pet_skin:
        clothes.append(pet_skin)

    weapon_skins = basic.get("weaponSkinShows", []) or []
    for w in weapon_skins:
        wid = w.get("skinId") if isinstance(w, dict) else w
        if wid:
            clothes.append(wid)

    item_ids = clothes[:len(OUTFIT_RING_SLOTS)]

    icon_bytes_list = await asyncio.gather(*[fetch_icon_bytes(i) for i in item_ids])

    if os.path.exists(OUTFIT_BG_FILE):
        bg = Image.open(OUTFIT_BG_FILE).convert("RGBA")
    else:
        bg = Image.new("RGBA", (1400, 1123), (10, 8, 30, 255))

    for (cx, cy, r), icon_bytes in zip(OUTFIT_RING_SLOTS, icon_bytes_list):
        if not icon_bytes:
            continue
        size = max(40, int(2 * (r - RING_PADDING)))
        icon = make_circular_icon(icon_bytes, size)
        bg.paste(icon, (cx - size // 2, cy - size // 2), icon)

    out = io.BytesIO()
    bg.save(out, "PNG")
    out.seek(0)
    return out

# ============= Routes =============
@app.route('/')
def web_ui():
    html = '''<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Free Fire Info API - KAWSAR</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    @import url('https://fonts.googleapis.com/css2?family=Orbitron:wght@500;700;900&family=Rajdhani:wght@500;600;700&display=swap');
    body {
      font-family: 'Rajdhani', 'Segoe UI', sans-serif;
      background:
        radial-gradient(ellipse at 20% 10%, rgba(120,60,220,0.25), transparent 45%),
        radial-gradient(ellipse at 85% 15%, rgba(40,140,220,0.2), transparent 40%),
        radial-gradient(ellipse at 50% 90%, rgba(90,40,180,0.25), transparent 50%),
        #05040f;
      background-attachment: fixed;
      color: #e8e6ff;
      min-height: 100vh;
      display: flex; flex-direction: column; align-items: center;
      padding: 20px;
    }
    body::before {
      content: ""; position: fixed; inset: 0; pointer-events: none; z-index: 0;
      background-image:
        radial-gradient(1px 1px at 10% 20%, #fff, transparent),
        radial-gradient(1px 1px at 80% 40%, #fff, transparent),
        radial-gradient(1px 1px at 40% 70%, #fff, transparent),
        radial-gradient(1px 1px at 60% 15%, #fff, transparent),
        radial-gradient(1px 1px at 90% 85%, #fff, transparent),
        radial-gradient(1px 1px at 25% 90%, #fff, transparent);
      opacity: 0.5;
    }
    .container { width: 100%; max-width: 600px; position: relative; z-index: 1; }
    h1 {
      font-family: 'Orbitron', sans-serif; font-weight: 900; text-align: center;
      letter-spacing: 1px; margin-bottom: 20px; font-size: 26px;
      background: linear-gradient(90deg, #9d7dff, #7ad8ff, #b98bff);
      -webkit-background-clip: text; background-clip: text; color: transparent;
      text-shadow: 0 0 30px rgba(150,120,255,0.4);
    }
    h2 {
      font-family: 'Orbitron', sans-serif; font-size: 15px; text-align: center;
      margin-bottom: 15px; letter-spacing: 2px; text-transform: uppercase; color: #b9a8ff;
    }
    .card {
      position: relative;
      background: linear-gradient(180deg, rgba(30,20,60,0.55), rgba(15,10,35,0.7));
      backdrop-filter: blur(10px);
      border: 1px solid rgba(150,120,255,0.35);
      border-radius: 14px; padding: 22px; margin-bottom: 20px;
      box-shadow: 0 0 25px rgba(100,60,220,0.15), inset 0 0 30px rgba(80,40,180,0.06);
    }
    .card::before, .card::after {
      content: ""; position: absolute; width: 18px; height: 18px;
      border-color: #8fd6ff; opacity: 0.9;
    }
    .card::before { top: -1px; left: -1px; border-top: 2px solid #8fd6ff; border-left: 2px solid #8fd6ff; border-radius: 6px 0 0 0; }
    .card::after { bottom: -1px; right: -1px; border-bottom: 2px solid #8fd6ff; border-right: 2px solid #8fd6ff; border-radius: 0 0 6px 0; }
    .input-group { margin-bottom: 15px; }
    label { display: block; margin-bottom: 6px; font-weight: 600; font-size: 13px; letter-spacing: 1px; text-transform: uppercase; color: #a99bdb; }
    input {
      width: 100%; padding: 12px 14px; border: 1px solid rgba(150,120,255,0.3);
      border-radius: 8px; background: rgba(10,6,25,0.6); color: #fff; font-size: 16px;
      font-family: 'Rajdhani', sans-serif;
    }
    input:focus { outline: none; border-color: #8fd6ff; box-shadow: 0 0 12px rgba(143,214,255,0.4); }
    input::placeholder { color: #7a71a3; }
    button {
      width: 100%; padding: 13px; border: none; border-radius: 8px;
      background: linear-gradient(90deg, #7b4dff, #4d9dff);
      color: white; font-weight: 700; font-size: 16px; letter-spacing: 1px;
      text-transform: uppercase; cursor: pointer; transition: 0.25s; margin-top: 6px;
      box-shadow: 0 0 18px rgba(123,77,255,0.4);
      font-family: 'Orbitron', sans-serif;
    }
    button:hover { box-shadow: 0 0 28px rgba(123,77,255,0.7); transform: translateY(-1px); }
    .result { margin-top: 15px; }
    .admin-btn {
      background: transparent; border: 1px solid rgba(150,120,255,0.4);
      color: #b9a8ff; box-shadow: none; font-family: 'Rajdhani', sans-serif; font-weight: 600;
    }
    .admin-btn:hover { box-shadow: 0 0 15px rgba(150,120,255,0.3); }
    .admin-panel { display: none; }
    .error { color: #ff6b8b; padding: 10px; text-align: center; }
    .loading { text-align: center; color: #8fd6ff; padding: 10px; }
    pre { text-align: left; font-size: 12px; white-space: pre-wrap; word-break: break-all; color: #cfcaf5; }
    .banner-wrap { width: 100%; overflow-x: auto; border-radius: 10px; margin-bottom: 15px; background: rgba(0,0,0,0.3); padding: 8px; border: 1px solid rgba(150,120,255,0.25); }
    .banner-img { display: block; max-width: 100%; height: auto; border-radius: 8px; margin: 0 auto; }
    .visual-group { margin-bottom: 14px; padding-bottom: 4px; border-bottom: 1px solid rgba(150,120,255,0.15); }
    .outfit-wrap { width: 100%; overflow-x: auto; border-radius: 10px; margin: 8px 0 15px; background: rgba(0,0,0,0.3); padding: 6px; border: 1px solid rgba(120,180,255,0.25); }
    .outfit-img { display: block; width: 100%; height: auto; border-radius: 8px; margin: 0 auto; }
    .profile-card { text-align: left; }
    .profile-name { font-family: 'Orbitron', sans-serif; font-size: 19px; font-weight: 700; text-align: center; margin-bottom: 14px; color: #dcd4ff; }
    .stat-group { background: rgba(255,255,255,0.04); border: 1px solid rgba(150,120,255,0.15); border-radius: 10px; padding: 10px 14px; margin-bottom: 12px; }
    .stat-group-title { font-family: 'Orbitron', sans-serif; font-weight: 700; opacity: 0.85; margin-bottom: 6px; font-size: 12px; text-transform: uppercase; letter-spacing: 1px; color: #8fd6ff; }
    .stat-row { display: flex; justify-content: space-between; padding: 5px 0; border-bottom: 1px solid rgba(255,255,255,0.06); font-size: 14px; }
    .stat-row:last-child { border-bottom: none; }
    .stat-label { opacity: 0.65; }
    .stat-value { font-weight: 700; text-align: right; color: #f0ecff; }
    .stat-block { margin-bottom: 6px; }
    .chip-wrap { display: flex; flex-wrap: wrap; gap: 6px; padding: 6px 0 4px; }
    .chip {
      background: rgba(143,214,255,0.1); border: 1px solid rgba(143,214,255,0.25);
      color: #cfe9ff; font-size: 12px; padding: 4px 10px; border-radius: 20px;
      font-family: 'Rajdhani', sans-serif; font-weight: 600;
    }
    @media (max-width: 400px) { .container { padding: 10px; } }
  </style>
</head>
<body>
  <div class="container">
    <h1>🔥 KAWSAR CODEX Free Fire Info</h1>
    <div class="card">
      <h2>Player Lookup</h2>
      <div class="input-group"><label>UID</label><input type="text" id="uid" placeholder="Enter UID (e.g., 5853144564)"></div>
      <div class="input-group"><label>API Key</label><input type="password" id="apiKey" placeholder="Enter your API key"></div>
      <button onclick="fetchInfo()">Get Info</button>
      <div id="result"></div>
    </div>
    <button class="admin-btn" onclick="toggleAdmin()">⚙️ Admin Panel</button>
    <div class="card admin-panel" id="adminPanel">
      <h2>Change API Key</h2>
      <div class="input-group"><label>Admin Key</label><input type="password" id="adminKey" placeholder="Enter admin key"></div>
      <div class="input-group"><label>New User Key</label><input type="text" id="newKey" placeholder="New API key"></div>
      <button onclick="changeKey()">Update Key</button>
      <div id="adminResult"></div>
    </div>
    <div style="text-align:center; margin-top:20px; opacity:0.7;"><small>Region priority: ME → BD → IND</small></div>
  </div>
  <script>
    function fetchInfo() {
      const uid = document.getElementById('uid').value.trim();
      const apiKey = document.getElementById('apiKey').value.trim();
      const resultDiv = document.getElementById('result');
      if (!uid || !apiKey) { resultDiv.innerHTML = '<div class="error">Please provide both UID and API Key</div>'; return; }
      resultDiv.innerHTML = '<div class="loading">Loading... (may take up to 20-30s on first request)</div>';

      fetch(`/get?uid=${uid}&key=${apiKey}`)
        .then(async r => {
          let data;
          try { data = await r.json(); }
          catch (parseErr) { throw new Error(`Server returned invalid response (status ${r.status})`); }
          if (!r.ok || data.error) { throw new Error(data.error || `Request failed (status ${r.status})`); }
          return data;
        })
        .then(data => {
          const acc = data.AccountInfo || {};
          const profile = data.AccountProfileInfo || {};
          const guild = data.GuildInfo || {};
          const images = data._images || {};

          const row = (label, value) => (value === undefined || value === null || value === '') ? '' :
            `<div class="stat-row"><span class="stat-label">${label}</span><span class="stat-value">${value}</span></div>`;

          const labelize = (key) => key
            .replace(/([a-z])([A-Z])/g, '$1 $2')
            .replace(/^./, c => c.toUpperCase());

          const formatTimestamp = (val) => {
            const n = Number(val);
            if (!n || String(val).length < 9) return val;
            const d = new Date(n * 1000);
            return isNaN(d.getTime()) ? val : d.toLocaleDateString();
          };

          const chipList = (label, arr) => {
            if (!arr || !arr.length) return '';
            const chips = arr.map(v => `<span class="chip">${typeof v === 'object' ? JSON.stringify(v) : v}</span>`).join('');
            return `<div class="stat-block">
              <div class="stat-row"><span class="stat-label">${label}</span><span class="stat-value">${arr.length} item${arr.length > 1 ? 's' : ''}</span></div>
              <div class="chip-wrap">${chips}</div>
            </div>`;
          };

          // যেকোনো অবজেক্ট থেকে সুন্দর stat-group বানানোর জেনারিক রেন্ডারার (raw JSON এর বদলে)
          const renderGroup = (title, obj) => {
            if (!obj || typeof obj !== 'object' || Object.keys(obj).length === 0) return '';
            let inner = '';
            for (const [k, v] of Object.entries(obj)) {
              if (v === null || v === undefined || v === '') continue;
              if (Array.isArray(v)) {
                inner += chipList(labelize(k), v);
              } else if (typeof v === 'object') {
                inner += renderGroup(labelize(k), v);
              } else if (/time|login/i.test(k)) {
                inner += row(labelize(k), formatTimestamp(v));
              } else {
                inner += row(labelize(k), v);
              }
            }
            if (!inner) return '';
            return `<div class="stat-group"><div class="stat-group-title">${title}</div>${inner}</div>`;
          };

          const knownKeys = ['AccountInfo', 'AccountProfileInfo', 'GuildInfo', '_images'];
          let extraSections = '';
          for (const [key, val] of Object.entries(data)) {
            if (knownKeys.includes(key)) continue;
            extraSections += renderGroup(labelize(key), val);
          }

          resultDiv.innerHTML = `
            <div class="profile-card">
              ${(images.banner || images.outfit) ? `
              <div class="visual-group">
                ${images.banner ? `
                <div class="banner-wrap">
                  <img class="banner-img" src="${images.banner}" alt="Player Banner">
                </div>` : ''}
                ${images.outfit ? `
                <div class="stat-group-title" style="margin-top:6px;">Equipped Outfit</div>
                <div class="outfit-wrap">
                  <img class="outfit-img" src="${images.outfit}" alt="Equipped Outfit">
                </div>` : ''}
              </div>` : ''}
              <div class="profile-name">${acc.AccountName || 'Unknown'}</div>
              <div class="stat-group">
                ${row('Level', acc.AccountLevel)}
                ${row('EXP', acc.AccountEXP)}
                ${row('Region', acc.AccountRegion)}
                ${row('Title', acc.Title)}
                ${row('Likes', acc.AccountLikes)}
                ${row('BR Rank Points', acc.BrRankPoint)}
                ${row('CS Rank Points', acc.CsRankPoint)}
                ${row('BR Max Rank', acc.BrMaxRank)}
                ${row('CS Max Rank', acc.CsMaxRank)}
                ${row('Account Created', formatTimestamp(acc.AccountCreateTime))}
                ${row('Last Login', formatTimestamp(acc.AccountLastLogin))}
                ${row('Release Version', acc.ReleaseVersion)}
              </div>
              ${guild.GuildName ? `
              <div class="stat-group">
                <div class="stat-group-title">Guild</div>
                ${row('Name', guild.GuildName)}
                ${row('Level', guild.GuildLevel)}
                ${row('Members', `${guild.GuildMember || '?'}/${guild.GuildCapacity || '?'}`)}
              </div>` : ''}
              ${chipList('Equipped Outfit IDs', profile.EquippedOutfit)}
              ${chipList('Equipped Skills', profile.EquippedSkills)}
              ${extraSections}
            </div>`;
        })
        .catch(e => resultDiv.innerHTML = `<div class="error">${e.message}</div>`);
    }
    function toggleAdmin() {
      const panel = document.getElementById('adminPanel');
      panel.style.display = panel.style.display === 'block' ? 'none' : 'block';
    }
    function changeKey() {
      const adminKey = document.getElementById('adminKey').value.trim();
      const newKey = document.getElementById('newKey').value.trim();
      const resDiv = document.getElementById('adminResult');
      if (!adminKey || !newKey) { resDiv.innerHTML = '<div class="error">Both fields required</div>'; return; }
      fetch(`/change_key?admin_key=${adminKey}&new_key=${newKey}`)
        .then(r => r.json())
        .then(data => {
          if (data.status === 'success') {
            resDiv.innerHTML = '<div style="color:lightgreen;">✅ Key updated successfully</div>';
            document.getElementById('apiKey').value = newKey;
          } else { resDiv.innerHTML = `<div class="error">${data.error || 'Unknown error'}</div>`; }
        })
        .catch(e => resDiv.innerHTML = `<div class="error">${e}</div>`);
    }
  </script>
</body>
</html>'''
    return render_template_string(html)

async def fetch_player_raw(uid):
    """একবার config+region লজিক রান করে raw account data রিটার্ন করে, অথবা None"""
    await update_config()
    if not config_ready():
        raise RuntimeError("Server config not ready, try again shortly")
    for region in REGION_PRIORITY:
        try:
            data = await GetAccountInformation(uid, region)
            if data:
                return data
        except Exception as e:
            print(f"❌ Region {region} failed: {e}")
            continue
    return None

@app.route('/get')
async def get_account_info():
    try:
        uid = request.args.get('uid')
        key = request.args.get('key')
        if not uid or not key:
            return jsonify({"error": "uid and key required"}), 400
        if not check_api_key(key):
            return jsonify({"error": "Invalid API key"}), 403

        print(f"🔍 UID: {uid} requested")
        try:
            raw_data = await fetch_player_raw(uid)
        except Exception as e:
            print(f"❌ fetch_player_raw crashed: {e}")
            return jsonify({"error": "Config service unreachable, try again"}), 503

        if not raw_data:
            return jsonify({"error": "Player not found"}), 404

        response_json = format_response(raw_data)

        # ব্যানার + আউটফিট ছবি একই রিকোয়েস্টে জেনারেট করে base64 হিসেবে এম্বেড করা,
        # যাতে ফ্রন্টএন্ডকে আলাদা করে আবার /banner, /outfit কল করতে না হয়
        try:
            banner_io, outfit_io = await asyncio.gather(
                generate_banner_png(raw_data),
                generate_outfit_png(raw_data),
            )
            response_json["_images"] = {
                "banner": "data:image/png;base64," + base64.b64encode(banner_io.getvalue()).decode(),
                "outfit": "data:image/png;base64," + base64.b64encode(outfit_io.getvalue()).decode(),
            }
        except Exception as e:
            print(f"❌ Image generation failed: {e}")
            response_json["_images"] = {"banner": None, "outfit": None}

        return jsonify(response_json)
    except Exception as e:
        # শেষ ভরসা: কিছুতেই যেন HTML error page ফেরত না যায়
        print(f"❌ Unhandled /get error: {e}")
        return jsonify({"error": f"Internal error: {str(e)}"}), 500

@app.route('/banner')
async def get_banner_image():
    try:
        uid = request.args.get('uid')
        key = request.args.get('key')
        if not uid or not key:
            return jsonify({"error": "uid and key required"}), 400
        if not check_api_key(key):
            return jsonify({"error": "Invalid API key"}), 403

        try:
            raw_data = await fetch_player_raw(uid)
        except Exception as e:
            print(f"❌ fetch_player_raw crashed: {e}")
            return jsonify({"error": "Config service unreachable, try again"}), 503

        if not raw_data:
            return jsonify({"error": "Player not found"}), 404

        img_io = await generate_banner_png(raw_data)
        return Response(img_io.getvalue(), mimetype="image/png")
    except Exception as e:
        print(f"❌ Unhandled /banner error: {e}")
        return jsonify({"error": f"Internal error: {str(e)}"}), 500

@app.route('/outfit')
async def get_outfit_image():
    try:
        uid = request.args.get('uid')
        key = request.args.get('key')
        if not uid or not key:
            return jsonify({"error": "uid and key required"}), 400
        if not check_api_key(key):
            return jsonify({"error": "Invalid API key"}), 403

        try:
            raw_data = await fetch_player_raw(uid)
        except Exception as e:
            print(f"❌ fetch_player_raw crashed: {e}")
            return jsonify({"error": "Config service unreachable, try again"}), 503

        if not raw_data:
            return jsonify({"error": "Player not found"}), 404

        img_io = await generate_outfit_png(raw_data)
        return Response(img_io.getvalue(), mimetype="image/png")
    except Exception as e:
        print(f"❌ Unhandled /outfit error: {e}")
        return jsonify({"error": f"Internal error: {str(e)}"}), 500

@app.route('/refresh')
async def refresh_tokens():
    await update_config()
    tasks = [create_jwt(r) for r in REGION_PRIORITY]
    await asyncio.gather(*tasks)
    return jsonify({"status": "refreshed", "count": len(cached_tokens)})

@app.route('/change_key')
def change_key_endpoint():
    admin_key = request.args.get('admin_key')
    new_key = request.args.get('new_key')
    if not admin_key or not new_key:
        return jsonify({"error": "admin_key and new_key required"}), 400
    if not check_admin_key(admin_key):
        return jsonify({"error": "Invalid admin key"}), 403
    key_store['api_key'] = base64.b64encode(new_key.encode()).decode()
    print(f"🔑 User API key changed to: {new_key}")
    return jsonify({"status": "success", "message": "API key updated"})

# ============= Entry =============
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get("PORT", 2590)))
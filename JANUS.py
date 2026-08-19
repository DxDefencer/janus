#!/usr/bin/env python3
"""
JANUS - Journaled Application Network Usage Scanner
by Tracewarden

Поиск проксивари, туннелей и аномальной сетевой активности по SRUM и кустам реестра.
Работает там, где нет Sysmon, EDR и расширенного аудита.

Установка:
    pip install dissect.esedb python-registry

Использование:
    python janus.py SRUDB.dat
    python janus.py SRUDB.dat --system SYSTEM --software SOFTWARE --ntuser NTUSER.DAT
    python janus.py SRUDB.dat --system SYSTEM --software SOFTWARE --persistence
    python janus.py SRUDB.dat --system SYSTEM --window "2026-08-18 10:00" "2026-08-18 12:00"
    python janus.py SRUDB.dat --app winproxy

Что дают кусты:
    SYSTEM     - буква тома вместо \\Device\\HarddiskVolume3, часовой пояс машины,
                 службы (персистентность прокси-софта)
    SOFTWARE   - SID -> имя пользователя, сети, задачи планировщика,
                 установленные программы с датой установки, ключи автозапуска
    NTUSER.DAT - UserAssist: запускал ли пользователь бинарь руками и сколько раз
"""
import argparse, collections, datetime, os, re, struct, sys

try:
    from dissect.esedb import EseDB
except ImportError:
    sys.exit("Нужен dissect.esedb:  pip install dissect.esedb")

try:
    from Registry import Registry
    HAVE_REGF = True
except ImportError:
    HAVE_REGF = False

__version__ = '2.0'

BANNER = r"""
     ██╗ █████╗ ███╗   ██╗██╗   ██╗███████╗
     ██║██╔══██╗████╗  ██║██║   ██║██╔════╝
     ██║███████║██╔██╗ ██║██║   ██║███████╗
██   ██║██╔══██║██║╚██╗██║██║   ██║╚════██║
╚█████╔╝██║  ██║██║ ╚████║╚██████╔╝███████║
 ╚════╝ ╚═╝  ╚═╝╚═╝  ╚═══╝ ╚═════╝ ╚══════╝
  Journaled Application Network Usage Scanner
  v%s  ·  by Tracewarden
""" % __version__


class C:
    """ANSI-цвета. Гасятся автоматически, если вывод не в терминал,
    задана переменная NO_COLOR или передан --no-color."""
    OFF = False
    _CODES = {
        'dim': '2', 'bold': '1',
        'red': '31', 'green': '32', 'yellow': '33',
        'blue': '34', 'magenta': '35', 'cyan': '36',
        'bred': '91', 'byellow': '93', 'bcyan': '96',
    }

    @classmethod
    def _w(cls, name, text):
        if cls.OFF or not text:
            return text
        return '\033[%sm%s\033[0m' % (cls._CODES[name], text)

    @classmethod
    def disable(cls):
        cls.OFF = True

    @classmethod
    def setup(cls, force_off=False):
        if force_off or os.environ.get('NO_COLOR') or not sys.stdout.isatty():
            cls.disable()
            return
        if os.name == 'nt':          # Win10+: включаем обработку VT-последовательностей
            try:
                import ctypes
                k = ctypes.windll.kernel32
                k.SetConsoleMode(k.GetStdHandle(-11), 7)
            except Exception:
                cls.disable()


def _c(name):
    return lambda t: C._w(name, t)


dim, bold = _c('dim'), _c('bold')
red, green, yellow = _c('red'), _c('green'), _c('yellow')
cyan, magenta = _c('cyan'), _c('magenta')
bred, byellow, bcyan = _c('bred'), _c('byellow'), _c('bcyan')

# критичность признака -> цвет
FLAG_COLOR = {
    'ПОСТОЯННО': bred, 'СИММЕТРИЧНО': bred, 'ОТДАЧА>ПРИЁМ': bred,
    'ИМЯ:PROXYWARE': bred, 'ИМЯ:TUNNEL': byellow, 'ПУТЬ:USER': yellow,
}


def paint_flag(f):
    for k, fn in FLAG_COLOR.items():
        if f.startswith(k):
            return fn(f)
    return f


def banner(quiet=False):
    if quiet:
        return
    print(bcyan(BANNER))


T_NET  = '{973F5D5C-1D90-4944-BE8E-24B94231A174}'
T_CONN = '{DD6636C4-8929-4683-974E-22C046A43763}'
T_APP  = '{D10CA2FE-6FCF-4F6D-848E-B2E99266FA89}'
OLE_EPOCH = datetime.datetime(1899, 12, 30)

PROXYWARE = ['repocket', 'geonode', 'honeygain', 'pawns', 'iproyal', 'packetstream',
             'peer2profit', 'traffmonetizer', 'earnapp', 'earn.fm', 'earnfm',
             'bitping', 'salad', 'proxyrack', 'nodepay', 'grass', 'speedshare',
             'wproxy', 'winproxy']
TUNNEL = ['ngrok', 'cloudflared', 'frpc', 'frps', 'chisel', 'localtonet', 'serveo',
          'playit', 'openvpn', 'wireguard', 'sing-box', 'xray', 'v2ray', 'clash',
          'tor.exe', 'softether', 'zerotier', 'tailscale']
USER_DIRS = ['\\users\\', '\\temp\\', '\\downloads\\', '\\desktop\\',
             '\\appdata\\', '\\programdata\\', '\\public\\']
# известный системный шум в ProgramData - не помечаем
USER_DIRS_SKIP = ['\\programdata\\microsoft\\windows defender\\',
                  '\\programdata\\nvidia', '\\programdata\\package cache\\']


# ─────────────────────────── общие утилиты ───────────────────────────

def ole_time(raw):
    """SRUM пишет TimeStamp как OLE automation date (float64), dissect отдаёт сырой int64."""
    if raw is None:
        return None
    return OLE_EPOCH + datetime.timedelta(days=struct.unpack('<d', struct.pack('<q', int(raw)))[0])


def filetime(raw):
    try:
        return datetime.datetime(1601, 1, 1) + datetime.timedelta(microseconds=int(raw) // 10)
    except Exception:
        return None


def decode_sid(b):
    try:
        rev, n = b[0], b[1]
        auth = int.from_bytes(b[2:8], 'big')
        subs = struct.unpack('<%dI' % n, b[8:8 + 4 * n])
        return 'S-%d-%d-' % (rev, auth) + '-'.join(map(str, subs))
    except Exception:
        return b.hex()


def mb(n):
    return n / 1048576


# ─────────────────────────── работа с кустами ───────────────────────────

class Hives:
    """Обёртка над кустами. Любой из них опционален - без них скрипт работает как v1."""

    def __init__(self, system=None, software=None, ntuser=None):
        self.volumes = {}      # 'harddiskvolume3' -> 'C:'
        self.tz_name = None
        self.tz_offset = None  # минуты от UTC
        self.services = {}     # имя -> (ImagePath, Start)
        self.sids = {}         # SID -> имя пользователя
        self.networks = {}     # ProfileIndex -> имя сети
        self.net_profiles = [] # (имя, создан, последнее подключение)
        self.installed = []    # (имя, издатель, дата, путь)
        self.autoruns = []     # (куст, ключ, значение, данные)
        self.userassist = {}   # путь (lower) -> (кол-во запусков, последний запуск)
        self.tasks = []        # пути задач планировщика
        self.sysdrive = None   # 'C:'
        self.loaded = []

        if not HAVE_REGF and (system or software or ntuser):
            print('[!] python-registry не установлен - кусты пропущены (pip install python-registry)\n')
            return
        if system:
            self._system(system)
        if software:
            self._software(software)
        if ntuser:
            self._ntuser(ntuser)

    # --- вспомогательные ---
    @staticmethod
    def _open(path):
        return Registry.Registry(path)

    @staticmethod
    def _key(hive, path):
        """Разные тулзы выгружают кусты с корнем и без - пробуем оба варианта."""
        cands = [path]
        if '\\' in path:
            cands.append(path.split('\\', 1)[-1])
        for p in cands:
            try:
                return hive.open(p)
            except Exception:
                continue
        return None

    @staticmethod
    def _val(key, name, default=None):
        try:
            return key.value(name).value()
        except Exception:
            return default

    # --- SYSTEM ---
    def _system(self, path):
        try:
            h = self._open(path)
        except Exception as e:
            print('[!] SYSTEM не открылся: %s' % e); return
        self.loaded.append('SYSTEM')

        # какой ControlSet текущий
        cs = 'ControlSet001'
        sel = self._key(h, 'Select')
        if sel:
            n = self._val(sel, 'Current')
            if n:
                cs = 'ControlSet%03d' % int(n)

        # часовой пояс
        tz = self._key(h, '%s\\Control\\TimeZoneInformation' % cs)
        if tz:
            self.tz_name = self._val(tz, 'TimeZoneKeyName') or self._val(tz, 'StandardName')
            # ActiveTimeBias уже учитывает, действует ли сейчас летнее время.
            # Bias+DaylightBias складывать нельзя: в РФ DST отменён, но DaylightBias
            # в реестре всё равно -60, и сумма даёт лишний час.
            act = self._val(tz, 'ActiveTimeBias')
            if act is None:
                act = self._val(tz, 'Bias')
                sb = self._val(tz, 'StandardBias') or 0
                if act is not None:
                    act = act + sb
            if act is not None:
                self.tz_offset = -(act if act < 2**31 else act - 2**32)

        # службы - основной способ персистентности
        svc = self._key(h, '%s\\Services' % cs)
        if svc:
            for k in svc.subkeys():
                img = self._val(k, 'ImagePath')
                if img:
                    self.services[k.name()] = (str(img), self._val(k, 'Start'))

    # --- SOFTWARE ---
    def _software(self, path):
        try:
            h = self._open(path)
        except Exception as e:
            print('[!] SOFTWARE не открылся: %s' % e); return
        self.loaded.append('SOFTWARE')

        base = 'Microsoft\\Windows NT\\CurrentVersion'

        # системный диск - нужен для маппинга \device\harddiskvolumeN -> буква
        cv = self._key(h, base)
        if cv:
            sr = self._val(cv, 'SystemRoot') or self._val(cv, 'PathName')
            if sr and ':' in str(sr):
                self.sysdrive = str(sr)[:2].upper()

        # задачи планировщика - частый механизм персистентности
        tc = self._key(h, '%s\\Schedule\\TaskCache\\Tasks' % base)
        if tc:
            for k in tc.subkeys():
                p = self._val(k, 'Path')
                if p:
                    self.tasks.append(str(p))

        # SID -> пользователь
        pl = self._key(h, '%s\\ProfileList' % base)
        if pl:
            for k in pl.subkeys():
                p = self._val(k, 'ProfileImagePath')
                if p:
                    self.sids[k.name()] = str(p).rstrip('\\').split('\\')[-1]

        # профили сетей: имя, когда создан, когда последний раз подключались
        nl = self._key(h, '%s\\NetworkList\\Profiles' % base)
        if nl:
            for k in nl.subkeys():
                name = self._val(k, 'ProfileName')
                if name:
                    self.net_profiles.append((str(name),
                                              self._systemtime(self._val(k, 'DateCreated')),
                                              self._systemtime(self._val(k, 'DateLastConnected'))))

        # L2ProfileId -> SSID (через WlanSvc, best-effort)
        wl = self._key(h, 'Microsoft\\WlanSvc\\Interfaces')
        if wl:
            for iface in wl.subkeys():
                try:
                    profs = iface.subkey('Profiles')
                except Exception:
                    continue
                for p in profs.subkeys():
                    idx = self._val(p, 'ProfileIndex')
                    ssid = None
                    try:
                        meta = p.subkey('MetaData')
                        hints = self._val(meta, 'Channel Hints')
                        if hints:
                            hints = bytes(hints)
                            ln = struct.unpack('<I', hints[:4])[0]
                            ssid = hints[4:4 + ln].decode('utf-8', 'replace')
                    except Exception:
                        pass
                    if idx is not None and ssid:
                        self.networks[int(idx)] = ssid

        # установленные программы
        for wow in ('', 'Wow6432Node\\'):
            un = self._key(h, '%sMicrosoft\\Windows\\CurrentVersion\\Uninstall' % wow)
            if not un:
                continue
            for k in un.subkeys():
                name = self._val(k, 'DisplayName')
                if name:
                    self.installed.append((str(name),
                                           str(self._val(k, 'Publisher') or ''),
                                           str(self._val(k, 'InstallDate') or ''),
                                           str(self._val(k, 'InstallLocation') or '')))

        # автозапуск
        for sub in ('Microsoft\\Windows\\CurrentVersion\\Run',
                    'Microsoft\\Windows\\CurrentVersion\\RunOnce',
                    'Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Run'):
            k = self._key(h, sub)
            if k:
                for v in k.values():
                    self.autoruns.append(('SOFTWARE', sub, v.name(), str(v.value())))

    # --- NTUSER.DAT ---
    def _ntuser(self, path):
        try:
            h = self._open(path)
        except Exception as e:
            print('[!] NTUSER.DAT не открылся: %s' % e); return
        self.loaded.append('NTUSER')

        for sub in ('Software\\Microsoft\\Windows\\CurrentVersion\\Run',
                    'Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce'):
            k = self._key(h, sub)
            if k:
                for v in k.values():
                    self.autoruns.append(('NTUSER', sub, v.name(), str(v.value())))

        # UserAssist: ROT13 в именах, счётчик и время последнего запуска в данных
        ua = self._key(h, 'Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist')
        if not ua:
            return
        for guid in ua.subkeys():
            try:
                cnt = guid.subkey('Count')
            except Exception:
                continue
            for v in cnt.values():
                try:
                    raw = v.name()
                    if raw.startswith('UEME_'):     # служебные счётчики сессий
                        continue
                    name = _rot13(raw)
                    data = bytes(v.value())
                    if len(data) >= 68:
                        runs = struct.unpack('<I', data[4:8])[0]
                        last = filetime(struct.unpack('<Q', data[60:68])[0])
                    else:
                        runs, last = None, None
                    self.userassist[name.lower()] = (runs, last)
                except Exception:
                    pass

    @staticmethod
    def _systemtime(b):
        """SYSTEMTIME из NetworkList - 16 байт."""
        try:
            b = bytes(b)
            y, mo, _, d, hh, mi, ss, _ = struct.unpack('<8H', b[:16])
            return datetime.datetime(y, mo, d, hh, mi, ss)
        except Exception:
            return None

    def infer_volumes(self, apps):
        """MountedDevices не содержит маппинга HarddiskVolumeN -> буква.
        Определяем системный том по тому, в котором лежит \\windows\\system32."""
        if not self.sysdrive:
            return
        for a in apps:
            m = re.match(r'\\device\\(harddiskvolume\d+)\\windows\\system32\\', a, re.I)
            if m:
                self.volumes[m.group(1).lower()] = self.sysdrive
                return

    # --- применение к путям ---
    def pretty(self, path):
        """\\device\\harddiskvolume3\\... -> C:\\..."""
        if not self.volumes:
            return path
        m = re.match(r'\\device\\(harddiskvolume\d+)\\(.*)', path, re.I)
        if m and m.group(1).lower() in self.volumes:
            return '%s\\%s' % (self.volumes[m.group(1).lower()], m.group(2))
        return path

    def local(self, dt):
        if dt is None or self.tz_offset is None:
            return None
        return dt + datetime.timedelta(minutes=self.tz_offset)


def _hit(low, words):
    for w in words:
        if w.endswith('.exe'):
            if re.search(r'(?:^|[\\/])' + re.escape(w), low):
                return True
        elif w in low:
            return True
    return False


def _rot13(s):
    out = []
    for c in s:
        if 'a' <= c <= 'z':
            out.append(chr((ord(c) - 97 + 13) % 26 + 97))
        elif 'A' <= c <= 'Z':
            out.append(chr((ord(c) - 65 + 13) % 26 + 65))
        else:
            out.append(c)
    return ''.join(out)


# ─────────────────────────── SRUM ───────────────────────────

def build_idmap(db):
    idmap = {}
    for r in db.table('SruDbIdMapTable').records():
        blob = r.get('IdBlob')
        if blob is None:
            continue
        idx, itype = int(r.get('IdIndex')), int(r.get('IdType'))
        if itype == 3:
            idmap[idx] = 'SID:' + decode_sid(bytes(blob))
        else:
            try:
                idmap[idx] = bytes(blob).decode('utf-16-le').rstrip('\x00')
            except Exception:
                idmap[idx] = bytes(blob).hex()
    return idmap


def load_net(db, idmap):
    rows = []
    for r in db.table(T_NET).records():
        t = ole_time(r.get('TimeStamp'))
        if not t:
            continue
        rows.append({
            't':    t,
            'app':  idmap.get(int(r.get('AppId')), '<AppId=%s unattributed>' % r.get('AppId')),
            'user': idmap.get(int(r.get('UserId') or 0), ''),
            'l2':   r.get('L2ProfileId'),
            'sent': int(r.get('BytesSent') or 0),
            'recv': int(r.get('BytesRecvd') or 0),
        })
    return rows


def first_seen(db, idmap):
    fs = {}
    for r in db.table(T_APP).records():
        app = idmap.get(int(r.get('AppId')))
        t = ole_time(r.get('TimeStamp'))
        if app and t:
            a = app.lower()
            if a not in fs or t < fs[a]:
                fs[a] = t
    return fs


# ─────────────────────────── отчёты ───────────────────────────

def report(rows, fs, hv):
    total = len(set(x['t'] for x in rows))
    agg = collections.defaultdict(lambda: {'sent': 0, 'recv': 0, 'slots': set(),
                                           'users': set(), 'nets': set()})
    for x in rows:
        a = agg[x['app']]
        a['sent'] += x['sent']; a['recv'] += x['recv']; a['slots'].add(x['t'])
        if x['user']:
            a['users'].add(x['user'])
        if x['l2'] is not None:
            a['nets'].add(int(x['l2']) & 0xFFFF)

    lo, hi = min(x['t'] for x in rows), max(x['t'] for x in rows)
    print(dim('=' * 100))
    print('ОХВАТ (UTC): %s -> %s   |   часовых слотов: %d' % (lo, hi, total))
    if hv.tz_offset is not None:
        print('ЧАСОВОЙ ПОЯС МАШИНЫ: %s (UTC%+d:%02d)  ->  локально: %s - %s'
              % (hv.tz_name, hv.tz_offset // 60, abs(hv.tz_offset) % 60,
                 hv.local(lo), hv.local(hi)))
    if hv.volumes:
        print('ТОМА: %s' % ', '.join('%s=%s' % (k, v) for k, v in sorted(hv.volumes.items())))
    if hv.loaded:
        print('КУСТЫ: %s' % ', '.join(hv.loaded))
    print(dim('=' * 100))

    scored = []
    for app, a in agg.items():
        sent, recv, n = a['sent'], a['recv'], len(a['slots'])
        if sent + recv < 1_000_000:
            continue
        cover = n / total
        ratio = sent / recv if recv else 999
        flags = []
        low = app.lower()
        if cover >= 0.90:
            flags.append('ПОСТОЯННО(%d%%)' % (cover * 100))
        if 0.8 <= ratio <= 1.25 and sent > 50_000_000:
            flags.append('СИММЕТРИЧНО(%.2f)' % ratio)
        if ratio > 1.5 and sent > 20_000_000:
            flags.append('ОТДАЧА>ПРИЁМ(%.1f)' % ratio)
        if _hit(low, PROXYWARE):
            flags.append('ИМЯ:PROXYWARE')
        if _hit(low, TUNNEL):
            flags.append('ИМЯ:TUNNEL')
        if any(d in low for d in USER_DIRS) and not any(d in low for d in USER_DIRS_SKIP):
            flags.append('ПУТЬ:USER')
        # --- обогащение из кустов ---
        reg = []
        svc = match_service(app, hv)
        if svc:
            reg.append('СЛУЖБА: %s (Start=%s)' % svc)
        ua = match_userassist(app, hv)
        if ua:
            reg.append('USERASSIST: запусков %s, последний %s' % ua)
        ar = match_autorun(app, hv)
        if ar:
            reg.append('АВТОЗАПУСК: %s\\%s' % ar)
        tk = match_task(app, hv)
        if tk:
            reg.append('ЗАДАЧА ПЛАНИРОВЩИКА: %s' % tk)
        scored.append((len(flags), sent, app, sent, recv, n, cover, flags, reg, a))

    scored.sort(key=lambda x: (-x[0], -x[1]))
    print(bold('\n### ПОДОЗРИТЕЛЬНЫЕ\n'))
    print('%10s %10s %6s %6s  %s' % ('SENT MB', 'RECV MB', 'часов', 'covr', 'APP'))
    print(dim('-' * 100))
    for nf, _, app, sent, recv, n, cover, flags, reg, a in scored:
        if not flags and not reg:
            continue
        name = hv.pretty(app)[-70:]
        print('%10.1f %10.1f %6d %5.0f%%  %s' % (mb(sent), mb(recv), n, cover * 100,
                                                 bold(name) if len(flags) >= 3 else name))
        if flags:
            print('%36s  %s %s' % ('', bold('^'),
                                   dim(' | ').join(paint_flag(f) for f in flags)))
        for line in reg:
            print('%36s  %s %s' % ('', bold('*'), cyan(line)))
        if app.lower() in fs:
            print('%36s  %s %s' % ('', bold('*'),
                                   cyan('первое появление: %s' % fs[app.lower()])))
        users = [hv.sids.get(u[4:], u) if u.startswith('SID:') else u for u in a['users']]
        if users:
            print('%36s  %s %s' % ('', bold('*'), cyan('пользователь: %s' % ', '.join(users))))
        nets = [hv.networks.get(i, str(i)) for i in a['nets']]
        if hv.networks and nets:
            print('%36s  %s %s' % ('', bold('*'), cyan('сети: %s' % ', '.join(nets))))
        print()

    print(bold('\n### ОСТАЛЬНОЕ (топ-20 по отдаче)\n'))
    print('%10s %10s %6s  %s' % ('SENT MB', 'RECV MB', 'часов', 'APP'))
    print(dim('-' * 100))
    for _, _, app, sent, recv, n, _, flags, reg, _ in [s for s in scored if not s[7] and not s[8]][:20]:
        print('%10.1f %10.1f %6d  %s' % (mb(sent), mb(recv), n, hv.pretty(app)[-70:]))


def match_service(app, hv):
    exe = app.lower().split('\\')[-1]
    for name, (img, start) in hv.services.items():
        if exe and exe in img.lower():
            return (name, start)
    return None


def match_userassist(app, hv):
    exe = app.lower().split('\\')[-1]
    for path, (runs, last) in hv.userassist.items():
        if exe and exe in path:
            return (runs, last)
    return None


def match_task(app, hv):
    """Задача может называться и по бинарю, и по каталогу установки:
    winproxy.exe лежит в \\Program Files\\WProxy\\, а задача - \\WProxy\\Repocket."""
    low = app.lower().replace('.exe', '')
    parts = [p for p in low.split('\\') if len(p) > 3
             and p not in ('device', 'program files', 'program files (x86)',
                           'users', 'appdata', 'local', 'roaming', 'windows',
                           'system32', 'current', 'bin', 'temp')]
    hits = []
    for t in hv.tasks:
        tl = t.lower()
        for p in parts:
            if p in tl:
                hits.append(t)
                break
    return hits[0] if hits else None


def match_autorun(app, hv):
    exe = app.lower().split('\\')[-1]
    for hive, key, name, data in hv.autoruns:
        if exe and exe in data.lower():
            return (hive, name)
    return None


def persistence(hv):
    print(bold('### АВТОЗАПУСК\n'))
    if not hv.autoruns:
        print('  (нет данных - нужны --software / --ntuser)')
    for hive, key, name, data in hv.autoruns:
        f = flagwords(data)
        mark = '  %s %s' % (bold('<=='), bred(f)) if f else ''
        print('  [%-8s] %-30s = %s%s' % (hive, name[:30], data[:90], mark))

    print(bold('\n### СЛУЖБЫ С ПОДОЗРИТЕЛЬНЫМ ImagePath\n'))
    if not hv.services:
        print('  (нет данных - нужен --system)')
    for name, (img, start) in sorted(hv.services.items()):
        f = flagwords(img)
        if f:
            print('  %-35s Start=%-3s %s' % (name[:35], start, img[:80]))
            print('  %35s  %s %s' % ('', bold('<=='), bred(f)))

    print(bold('\n### УСТАНОВЛЕННЫЕ ПРОГРАММЫ (совпадения по спискам)\n'))
    if not hv.installed:
        print('  (нет данных - нужен --software)')
    for name, pub, date, loc in sorted(hv.installed):
        f = flagwords(name + ' ' + loc)
        if f:
            print('  %-40s  издатель=%-22s установлено=%s' % (name[:40], pub[:22], date))
            print('  %-40s  путь=%s' % ('', loc))
            print('  %-40s  %s %s' % ('', bold('<=='), bred(f)))

    print(bold('\n### ЗАДАЧИ ПЛАНИРОВЩИКА (совпадения по спискам)\n'))
    if not hv.tasks:
        print('  (нет данных - нужен --software)')
    for t in sorted(hv.tasks):
        f = flagwords(t)
        if f:
            print('  %-55s  %s %s' % (t[:55], bold('<=='), bred(f)))

    if hv.net_profiles:
        print(bold('\n### ПРОФИЛИ СЕТЕЙ\n'))
        for name, created, last in sorted(hv.net_profiles, key=lambda x: x[2] or datetime.datetime.min):
            print('  %-40s создан=%s  последнее подключение=%s' % (name[:40], created, last))

    if hv.userassist:
        print(bold('\n### USERASSIST (совпадения по спискам)\n'))
        for path, (runs, last) in sorted(hv.userassist.items()):
            f = flagwords(path)
            if f:
                print('  запусков=%-4s последний=%s  %s' % (runs, last, path[:70]))
                print('  %-40s  %s %s' % ('', bold('<=='), bred(f)))


def flagwords(s):
    """Слова с .exe матчим по границе имени файла, иначе locator.exe ловится как tor.exe."""
    low = s.lower()
    hits = []
    for w in PROXYWARE + TUNNEL:
        if w.endswith('.exe'):
            if re.search(r'(?:^|[\\/\s"\'])' + re.escape(w), low):
                hits.append(w)
        elif w in low:
            hits.append(w)
    if any(d in low for d in USER_DIRS) and not any(d in low for d in USER_DIRS_SKIP):
        hits.append('ПУТЬ:USER')
    return ', '.join(hits)


def window(rows, lo, hi, hv):
    sel = sorted([x for x in rows if lo <= x['t'] <= hi], key=lambda x: (x['t'], -x['sent']))
    print('### ОКНО %s - %s UTC  (записей: %d)' % (lo, hi, len(sel)))
    if hv.tz_offset is not None:
        print('### локально: %s - %s (%s)\n' % (hv.local(lo), hv.local(hi), hv.tz_name))
    print('%-15s %-8s %12s %12s  %s' % ('UTC', 'локал.', 'SENT', 'RECV', 'APP'))
    print(dim('-' * 105))
    for x in sel:
        loc = hv.local(x['t'])
        print('%-15s %-8s %12s %12s  %s'
              % (x['t'].strftime('%m-%d %H:%M'), loc.strftime('%H:%M') if loc else '-',
                 format(x['sent'], ','), format(x['recv'], ','), hv.pretty(x['app'])[-55:]))


def detail(rows, fs, needle, hv):
    sel = sorted([x for x in rows if needle.lower() in x['app'].lower()], key=lambda x: x['t'])
    if not sel:
        print('не найдено:', needle); return
    for app in sorted(set(x['app'] for x in sel)):
        s = [x for x in sel if x['app'] == app]
        hours = collections.Counter(x['t'].hour for x in s)
        tot_s, tot_r = sum(x['sent'] for x in s), sum(x['recv'] for x in s)
        print('\n--- %s' % hv.pretty(app))
        print('    первое в сети : %s' % s[0]['t'])
        print('    последнее     : %s' % s[-1]['t'])
        print('    первое вообще : %s' % fs.get(app.lower(), 'н/д'))
        print('    слотов        : %d' % len(s))
        print('    sent/recv     : %.1f MB / %.1f MB  (ratio %.2f)'
              % (mb(tot_s), mb(tot_r), tot_s / max(1, tot_r)))
        print('    часы (UTC)    : %s' % sorted(hours))
        svc = match_service(app, hv)
        if svc:
            print('    служба        : %s (Start=%s)' % svc)
        ua = match_userassist(app, hv)
        if ua:
            print('    UserAssist    : запусков %s, последний %s' % ua)
        ar = match_autorun(app, hv)
        if ar:
            print('    автозапуск    : %s / %s' % ar)
        tk = match_task(app, hv)
        if tk:
            print('    задача        : %s' % tk)


def main():
    p = argparse.ArgumentParser(
        prog='janus',
        description='JANUS %s - поиск проксивари и туннелей в SRUM' % __version__)
    p.add_argument('db')
    p.add_argument('--system',   help='куст SYSTEM')
    p.add_argument('--software', help='куст SOFTWARE')
    p.add_argument('--ntuser',   help='куст NTUSER.DAT пользователя')
    p.add_argument('--window', nargs=2, metavar=('FROM', 'TO'))
    p.add_argument('--app')
    p.add_argument('--persistence', action='store_true',
                   help='только автозапуск/службы/установленное - без SRUM')
    p.add_argument('--no-color', action='store_true',
                   help='без ANSI-цветов (гасятся сами вне терминала и при NO_COLOR)')
    p.add_argument('--no-banner', action='store_true',
                   help='не печатать заставку (для пайпов и автоматизации)')
    p.add_argument('--version', action='version',
                   version='JANUS %s - Journaled Application Network Usage Scanner' % __version__)
    a = p.parse_args()

    C.setup(a.no_color)
    banner(a.no_banner or not sys.stdout.isatty())

    hv = Hives(a.system, a.software, a.ntuser)

    if a.persistence:
        persistence(hv); return

    with open(a.db, 'rb') as f:
        db = EseDB(f)
        idmap = build_idmap(db)
        rows = load_net(db, idmap)
        fs = first_seen(db, idmap)
        hv.infer_volumes(set(x['app'] for x in rows))
        print('[+] AppId: %d, строк трафика: %d, кустов: %d\n'
              % (len(idmap), len(rows), len(hv.loaded)))
        if a.window:
            fmt = '%Y-%m-%d %H:%M'
            window(rows, datetime.datetime.strptime(a.window[0], fmt),
                   datetime.datetime.strptime(a.window[1], fmt), hv)
        elif a.app:
            detail(rows, fs, a.app, hv)
        else:
            report(rows, fs, hv)


if __name__ == '__main__':
    main()

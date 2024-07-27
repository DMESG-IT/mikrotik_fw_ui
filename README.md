
# DMESG # Mikrotik FW UI BASIC

Bu proje, www.dmesg.com.tr tarafından kullanılan bir yönetim paneli uygulamasıdır. Flask ve Mikrotik RouterOS API kullanılarak geliştirilmiştir. Proje, sunucu güvenliği ve yönetimi için engellenen ülkeler, ASN'ler ve IP adresleri üzerinde işlemler yapmanıza olanak tanır. 

## Özellikler

- **Engellenen Ülkeler:**
  - Ülkeleri engelleyebilir ve hız limitleri belirleyebilirsiniz.
  - Engellenen ülkelerden gelen trafiği Mikrotik RouterOS üzerinde bloklayabilirsiniz.

- **Engellenen ASN'ler:**
  - ASN numaralarını engelleyebilir ve hız limitleri belirleyebilirsiniz.
  - Engellenen ASN'lerden gelen trafiği Mikrotik RouterOS üzerinde bloklayabilirsiniz.

- **IP Adres Listeleri:**
  - IP adreslerini beyaz listeye veya kara listeye ekleyebilirsiniz.
  - Beyaz listedeki IP adresleri için Mikrotik RouterOS üzerinde kabul kuralları oluşturabilirsiniz.
  - Kara listedeki IP adresleri için Mikrotik RouterOS üzerinde bloklama kuralları oluşturabilirsiniz.


  
## Docker ile çalıştırmak
   ```plaintext
docker-compose up --build
 ```
Proje dizin yapısı

   ```plaintext
.
├── Dockerfile
├── docker-compose.yml
├── requirements.txt
├── app.py
├── update_mikrotik.py
├── templates
│   └── index.html
└── .env
 ```


## Kurulum

1. **Gerekli Bağımlılıkları Yükleyin:**
   ```bash
   pip install -r requirements.txt
   ```

2. **Çevresel Değişkenleri Ayarlayın:**
   `.env` dosyasını oluşturun ve Mikrotik Router bilgilerini girin:
   ```plaintext
   MIKROTIK_HOST=192.168.88.1
   MIKROTIK_USER=admin
   MIKROTIK_PASSWORD=yourpassword
   ```

3. **Veritabanı Dosyasını Oluşturun:**
   `data.json` dosyasını `/app/data` dizininde oluşturun:
   ```json
   {
       "blocked_countries": [],
       "blocked_asns": [],
       "settings": [],
       "last_update": "",
       "whitelist_ips": [],
       "blocked_ips": []
   }
   ```

4. **Uygulamayı Çalıştırın:**
   ```bash
   python app.py
   ```

## Kullanım

### Ülke Ekleme

1. Ana sayfada "Engellenen Ülkeler" bölümünde bir ülke seçin.
2. Hız limitini girin (isteğe bağlı).
3. "Ülke Ekle" butonuna tıklayın.

### ASN Ekleme

1. Ana sayfada "Engellenen ASN'ler" bölümünde ASN numarasını girin.
2. Hız limitini girin (isteğe bağlı).
3. "ASN Ekle" butonuna tıklayın.

### IP Adresi Ekleme

1. Ana sayfada "IP Adres Listeleri" bölümünde IP adresini girin.
2. Beyaz liste veya kara listeyi seçin.
3. "IP Ekle" butonuna tıklayın.


## Geliştirme

Proje, ChatGPT-4 tarafından saatlerce süren bir tasarım ve geliştirme süreciyle oluşturulmuştur. Flask, Bootstrap 5 ve Mikrotik RouterOS API kullanılarak modern ve kullanıcı dostu bir yönetim paneli sunar.

### Katkıda Bulunma

Katkıda bulunmak isterseniz, lütfen bir pull request oluşturun veya bir issue açın.

## Lisans

Bu proje MIT lisansı ile lisanslanmıştır. Daha fazla bilgi için `LICENSE` dosyasına bakın.

# Ebeveyn Kontrolü — Android 8–16

Bu sürüm çocuk/ebeveyn cihazı ayrımı, uzaktan politika, konum, kullanım ve cihaz durumu özelliklerini içerir.

## Özellikler
- Android 8 (API 26) ve üzeri
- Ebeveyn tarafından çocuk ekleme, ad değiştirme ve politika yönetimi
- Günlük toplam ekran süresi ve uygulama bazlı süre sınırları
- Uygulama engelleme
- Konum ve son konum geçmişi (sunucuda son 100 kayıt)
- Pil ve ağ durumu
- Ebeveyn tarafından "Telefonu çaldır" komutu; çocuk cihazı çevrimiçi olduğunda varsayılan zil sesini 60 saniyeye kadar çalar
- Çocuk tarafında günlük sınır ve kurallar yalnızca bilgi amaçlıdır
- Çocuk cihazında sunucu ayarları ilk kurulumdan sonra kilitlenir
- Çocuk telemetrisi ayrı `deviceToken` ile doğrulanır; yönetim endpointleri yalnızca ebeveyn API anahtarını kabul eder
- Yeniden başlatma sonrasında konum servisini yeniden başlatmak için BOOT_COMPLETED alıcısı
- Android'in foreground location service bildirimi sistem tarafından zorunlu tutulabildiği için tamamen gizlenmez; bildirim sessiz/minimaldir.

## Kurulum
1. `server` klasöründe `npm install`.
2. `API_KEY` ortam değişkenini ayarlayın.
3. `npm start` ile sunucuyu çalıştırın.
4. Ebeveyn uygulamasında API adresi ve API anahtarını girin.
5. Çocuk cihazında ilk kurulum sırasında aynı sunucu adresi ve kurulum anahtarı ile cihazı kaydedin. Başarılı kayıttan sonra çocuk uygulaması `deviceToken` alır ve API anahtarını yerel tercihlerden siler.

## Önemli
Sunucu bellekte veri tutar; üretim ortamında veritabanı, HTTPS, kullanıcı hesabı/oturum yönetimi ve anahtar rotasyonu eklenmelidir.
